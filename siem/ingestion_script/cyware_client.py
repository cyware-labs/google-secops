# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


"""Cyware CTIX Client for API calls."""

import base64
import datetime
import hashlib
import hmac
import time
import traceback
from typing import Any, Dict, Optional, Union
import requests
from urllib.parse import urlencode
from urllib.parse import quote

# from google3.third_party.chronicle.ingestion_scripts.common import ingest_v1
# from google3.third_party.chronicle.ingestion_scripts.common import utils

from common import ingest_v1
from common import utils

# copybara:strip_begin(imports)
# from google3.third_party.chronicle.ingestion_scripts.cyware_threat_intelligence_exchange import (
#     constant,
# )
# from google3.third_party.chronicle.ingestion_scripts.cyware_threat_intelligence_exchange import (
#     exception_handler,
# )
# from google3.third_party.chronicle.ingestion_scripts.cyware_threat_intelligence_exchange import (
#     utility,
# )
# copybara:strip_end_and_replace_begin
import constant
import exception_handler
import utility
# copybara:replace_end


class CTIXClient:
    """Cyware CTIX Client to handle all API operations."""

    def __init__(
        self,
        base_url: str,
        access_id: str,
        secret_key: str,
        tenant_name: str,
        enrichment_enabled: bool = False,
        label_name: Optional[str] = None,
        bucket_name: str = None,
        lookback_days: Optional[str] = None,
    ) -> None:
        """Initialize CTIX Client with required credentials."""
        self.base_url = base_url.rstrip("/")
        self.access_id = access_id
        self.secret_key = secret_key
        self.tenant_name = tenant_name
        self.label_name = label_name
        self.enrichment_enabled = enrichment_enabled
        self.bucket_name = bucket_name
        self.lookback_days = lookback_days
        utils.cloud_logging("Cyware CTIX Client Initialized.", severity="INFO")

    @exception_handler.exception_handler(action_name="CTIX REST API")
    def _ctix_rest_api(self, method, url, params, json_body=None):
        """Make API call to CTIX.

        Args:
            method (str): HTTP method (GET or POST)
            url (str): Full URL to call
            params (dict): Query parameters with auth
            json_body (dict, optional): JSON body for POST requests

        Returns:
            dict: Dict containing response if call is successful.
        """
        return_dict = {"response": None, "status": False, "retry": False}
        encoded_label_name = ""
        if params.get("label_name"):
            safe_chars = constant.LABEL_NAME_SAFE_CHARS
            encoded_label_name = quote(
                params.get("label_name", ""), safe=safe_chars
            )
            del params["label_name"]
        encoded_params = urlencode(params)
        if encoded_label_name:
            encoded_url = (
                f"{url}?{encoded_params}&label_name={encoded_label_name}"
            )
        else:
            encoded_url = f"{url}?{encoded_params}"

        response = requests.request(
            method=method,
            url=encoded_url,
            headers={"User-Agent": constant.USER_AGENT_NAME},
            json=json_body,
            timeout=(constant.CONNECTION_TIMEOUT, constant.READ_TIMEOUT),
            verify=True,
        )
        return_dict["response"] = response
        return_dict["status"] = True
        return return_dict

    def _parse_and_handle_response(self, return_dict, result, fetch_type):
        """Parse and handle the API response.

        Args:
            return_dict (dict): dict containing the return values
            result (dict): api response
            fetch_type (str): to identify which api call response is passed

        Returns:
            dict: api call response
        """
        try:
            response = result["response"]
            return_dict["response"] = response
            if response.status_code == 200:
                return_dict["data"] = response.json()
                return_dict["status"] = True
            elif response.status_code == 401:
                return_dict["status"] = False
                return_dict["error"] = "Invalid API credentials."
                utils.cloud_logging(
                    constant.GENERAL_ERROR_MESSAGE.format(
                        status_code=response.status_code,
                        response_text=response.text,
                        fetch_type=fetch_type,
                    ),
                    severity="ERROR",
                )
            elif response.status_code == 403:
                return_dict["status"] = False
                return_dict["error"] = f"Access denied for {fetch_type}."
                utils.cloud_logging(
                    constant.GENERAL_ERROR_MESSAGE.format(
                        status_code=response.status_code,
                        response_text=response.text,
                        fetch_type=fetch_type,
                    ),
                    severity="ERROR",
                )
            elif response.status_code == 429:
                return_dict["status"] = False
                return_dict["retry"] = True
                return_dict["error"] = (
                    f"Rate limit exceeded while fetching {fetch_type}."
                )
                utils.cloud_logging(
                    constant.GENERAL_ERROR_MESSAGE.format(
                        status_code=response.status_code,
                        response_text=response.text,
                        fetch_type=fetch_type,
                    ),
                    severity="ERROR",
                )
            elif response.status_code >= 500:
                return_dict["status"] = False
                return_dict["retry"] = True
                return_dict["error"] = (
                    f"Server error while fetching {fetch_type}."
                )
                utils.cloud_logging(
                    constant.GENERAL_ERROR_MESSAGE.format(
                        status_code=response.status_code,
                        response_text=response.text,
                        fetch_type=fetch_type,
                    ),
                    severity="ERROR",
                )
            else:
                return_dict["status"] = False
                return_dict["error"] = (
                    f"Failed to fetch {fetch_type}, "
                    f"status code: {response.status_code}"
                )
                utils.cloud_logging(
                    constant.GENERAL_ERROR_MESSAGE.format(
                        status_code=response.status_code,
                        response_text=response.text,
                        fetch_type=fetch_type,
                    ),
                    severity="ERROR",
                )
        except ValueError as ex:
            utils.cloud_logging(
                f"Failed to parse response: "
                f"{result['response'].text}. Error: {ex}\n"
                f"Traceback: {traceback.format_exc()}",
                severity="ERROR",
            )
        except Exception as ex:  # pylint: disable=broad-except
            response = result.get("response")
            utils.cloud_logging(
                f"Error handling response. Response: "
                f"{response.text if response else 'N/A'}. "
                f"Error: {repr(ex)}\n"
                f"Traceback: {traceback.format_exc()}",
                severity="ERROR",
            )
        return return_dict

    def _log_and_sleep_before_retry(
        self, sleep_time=constant.DEFAULT_SLEEP_TIME
    ):
        """Log a retry message and sleep before retrying.

        Args:
            sleep_time (int): The time in seconds to sleep before retrying.
        """
        utils.cloud_logging(constant.RETRY_MESSAGE.format(sleep_time))
        time.sleep(sleep_time)

    def get_ctix_auth_params(
        self, access_id: str, secret_key: str
    ) -> Dict[str, Union[str, int]]:
        """Generate authentication query parameters for CTIX API requests."""
        expires = int(time.time()) + constant.SIGNATURE_EXPIRY_SECONDS
        to_sign = f"{access_id}\n{expires}"
        signature = base64.b64encode(
            hmac.new(
                secret_key.encode("utf-8"),
                to_sign.encode("utf-8"),
                hashlib.sha1,
            ).digest()
        ).decode("utf-8")
        return {
            "AccessID": access_id,
            "Expires": expires,
            "Signature": signature,
        }

    def make_api_call(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        fetch_type: str = "CTIX Data",
    ) -> Dict[str, Any]:
        """Make REST API call to CTIX with retry logic.

        Args:
            method (str): HTTP method (GET or POST)
            url (str): Full URL to call
            params (dict, optional): Query parameters
            json_body (dict, optional): JSON body for POST requests
            fetch_type (str): Type of data being fetched for logging

        Returns:
            dict: Response with status, data, and error fields
        """
        auth_params = self.get_ctix_auth_params(self.access_id, self.secret_key)
        all_params = {**auth_params, **(params or {})}

        return_dict = {"status": False, "data": {}, "error": "", "retry": False}
        count = 0
        result = {}
        while count < constant.RETRY_COUNT:
            result = self._ctix_rest_api(method, url, all_params, json_body)

            if result.get("retry") or not result.get("status"):
                if result.get("retry"):
                    count += 1
                    if count == constant.RETRY_COUNT:
                        return_dict.update(result)
                        return return_dict
                    self._log_and_sleep_before_retry()
                    continue
                return result

            result = self._parse_and_handle_response(
                return_dict, result, fetch_type
            )

            if result["status"]:
                return result
            if not result.get("retry", False):
                return result
            count += 1
            if count == constant.RETRY_COUNT:
                break
            self._log_and_sleep_before_retry()

        return_dict.update(result)
        return return_dict

    def get_saved_result_set_page(
        self, from_timestamp: int, to_timestamp: int, page: int
    ) -> Dict[str, Any]:
        """Get a single page of saved result set data from CTIX.

        Args:
            from_timestamp (int): Epoch timestamp to fetch data from
            to_timestamp (int): Epoch timestamp to fetch data to
            page (int): Page number to fetch

        Returns:
            dict: Response containing indicators and pagination info
        """
        url = f"{self.base_url}/{constant.SAVED_RESULT_SET_ENDPOINT}"
        params = {
            "page_size": constant.PAGE_SIZE_FOR_SAVED_RESULT,
            "page": page,
            "from_timestamp": from_timestamp,
            "to_timestamp": to_timestamp,
            "version": constant.CTIX_API_VERSION,
        }

        if self.label_name:
            escaped_label = self.label_name.replace("\\", "\\\\").replace(
                '"', '\\"'
            )
            params["label_name"] = escaped_label

        response = self.make_api_call("GET", url, params=params)

        if not response.get("status"):
            error_message = (
                f"Error fetching saved result set page {page}: "
                f"{response.get('error')}"
            )
            raise exception_handler.CywareCTIXException(error_message)

        return response.get("data", {})

    def _deduplicate_indicators(
        self, indicators: list[Dict[str, Any]]
    ) -> list[Dict[str, Any]]:
        """Deduplicate indicators by keeping only the latest based on
        ctix_modified.

        Args:
            indicators: List of indicator dictionaries

        Returns:
            Deduplicated list with only the latest version of each indicator
        """
        if not indicators:
            return []

        latest_indicators = {}
        missing_modified_count = 0
        missing_sdo_name_count = 0

        for indicator in indicators:
            sdo_name = indicator.get("sdo_name")
            ctix_modified = indicator.get("ctix_modified")

            if not sdo_name:
                utils.cloud_logging(
                    f"Indicator missing sdo_name field, skipping: "
                    f"{indicator.get('id')}",
                    severity="WARNING",
                )
                missing_sdo_name_count += 1
                continue

            if not ctix_modified:
                utils.cloud_logging(
                    f"Indicator {sdo_name} is missing ctix_modified field",
                    severity="WARNING",
                )
                missing_modified_count += 1
                if sdo_name not in latest_indicators:
                    latest_indicators[sdo_name] = indicator
                continue

            if sdo_name in latest_indicators:
                existing_modified = latest_indicators[sdo_name].get(
                    "ctix_modified"
                )
                if existing_modified and ctix_modified > existing_modified:
                    latest_indicators[sdo_name] = indicator
            else:
                latest_indicators[sdo_name] = indicator

        log_msgs = []
        if missing_sdo_name_count > 0:
            log_msgs.append(
                f"Found {missing_sdo_name_count} indicators "
                f"without sdo_name field"
            )
        if missing_modified_count > 0:
            log_msgs.append(
                f"Found {missing_modified_count} indicators "
                f"without ctix_modified field"
            )
        if log_msgs:
            utils.cloud_logging(", ".join(log_msgs), severity="WARNING")

        return list(latest_indicators.values())

    def _get_checkpoints_and_timestamps(self) -> tuple[int, int, int]:
        """Load checkpoints and calculate from/to timestamps with validation.

        Returns:
            tuple: (from_timestamp, to_timestamp, starting_page)
        """
        last_from_timestamp = utility.get_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_FROM_TIMESTAMP,
        )
        last_to_timestamp = utility.get_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_TO_TIMESTAMP,
        )
        last_page_number = utility.get_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_PAGE_NUMBER,
        )

        current_time = int(
            datetime.datetime.now(datetime.timezone.utc).timestamp()
        )

        if last_from_timestamp:
            try:
                from_timestamp = int(last_from_timestamp)
                if from_timestamp <= 0:
                    utils.cloud_logging(
                        f"Invalid from_timestamp checkpoint: {from_timestamp}"
                        f" (non-positive). Resetting to default based on"
                        f" lookback days.",
                        severity="WARNING",
                    )
                    from_timestamp = self.get_start_time(self.lookback_days)
                elif from_timestamp > current_time:
                    utils.cloud_logging(
                        f"Invalid from_timestamp checkpoint: {from_timestamp}"
                        f"(future timestamp)."
                        f"Resetting to default based on lookback days.",
                        severity="WARNING",
                    )
                    from_timestamp = self.get_start_time(self.lookback_days)
                else:
                    utils.cloud_logging(
                        f"Checkpoint exists, from_timestamp: {from_timestamp}",
                        severity="INFO",
                    )
            except (ValueError, TypeError) as e:
                utils.cloud_logging(
                    f"Invalid from_timestamp checkpoint: {last_from_timestamp} "
                    f"(not a valid number). "
                    f"Error: {repr(e)}. Resetting to default based on lookback"
                    f"days.\n"
                    f"Traceback: {traceback.format_exc()}",
                    severity="WARNING",
                )
                from_timestamp = self.get_start_time(self.lookback_days)
        else:
            from_timestamp = self.get_start_time(self.lookback_days)

        if last_to_timestamp:
            try:
                to_timestamp = int(last_to_timestamp)
                if to_timestamp <= 0:
                    utils.cloud_logging(
                        f"Invalid to_timestamp checkpoint: {to_timestamp} "
                        f"(non-positive). Resetting to current time.",
                        severity="WARNING",
                    )
                    to_timestamp = current_time
                    utility.set_last_checkpoint(
                        self.tenant_name,
                        self.bucket_name,
                        constant.CHECKPOINT_KEY_TO_TIMESTAMP,
                        None,
                    )
                elif to_timestamp > current_time:
                    utils.cloud_logging(
                        f"Invalid to_timestamp checkpoint: {to_timestamp} "
                        f"(future timestamp). Resetting to current time.",
                        severity="WARNING",
                    )
                    to_timestamp = current_time
                    utility.set_last_checkpoint(
                        self.tenant_name,
                        self.bucket_name,
                        constant.CHECKPOINT_KEY_TO_TIMESTAMP,
                        None,
                    )
                else:
                    utils.cloud_logging(
                        f"Checkpoint exists, to_timestamp: {to_timestamp}",
                        severity="INFO",
                    )
            except (ValueError, TypeError) as e:
                utils.cloud_logging(
                    f"Invalid to_timestamp checkpoint: "
                    f"{last_to_timestamp} (not a valid number). "
                    f"Error: {repr(e)}. Resetting to current time.\n"
                    f"Traceback: {traceback.format_exc()}",
                    severity="WARNING",
                )
                to_timestamp = current_time
                utility.set_last_checkpoint(
                    self.tenant_name,
                    self.bucket_name,
                    constant.CHECKPOINT_KEY_TO_TIMESTAMP,
                    None,
                )
        else:
            to_timestamp = current_time

        if from_timestamp >= to_timestamp:
            utils.cloud_logging(
                f"Invalid checkpoint state: from_timestamp "
                f"({from_timestamp}) >= to_timestamp ({to_timestamp}). "
                f"This creates a backwards or zero-length time window. "
                f"Resetting to_timestamp to current time.",
                severity="ERROR",
            )
            to_timestamp = current_time
            utility.set_last_checkpoint(
                self.tenant_name,
                self.bucket_name,
                constant.CHECKPOINT_KEY_TO_TIMESTAMP,
                None,
            )

        if last_page_number:
            try:
                starting_page = int(last_page_number)
                if starting_page <= 0:
                    utils.cloud_logging(
                        f"Invalid page_number checkpoint: {starting_page} "
                        f"(non-positive). Resetting to page 1.",
                        severity="WARNING",
                    )
                    starting_page = 1
                else:
                    utils.cloud_logging(
                        f"Resuming from page {starting_page}",
                        severity="INFO",
                    )
            except (ValueError, TypeError) as e:
                utils.cloud_logging(
                    f"Invalid page_number checkpoint: {last_page_number} "
                    f"(not a valid number). Error: {repr(e)}. "
                    f"Resetting to page 1.\n"
                    f"Traceback: {traceback.format_exc()}",
                    severity="WARNING",
                )
                starting_page = 1
        else:
            starting_page = 1

        return from_timestamp, to_timestamp, starting_page

    def _extract_indicators_from_page_data(
        self, data: Dict[str, Any]
    ) -> list[Dict[str, Any]]:
        """Extract and filter indicators from page data with deduplication.

        Note: Indicators are NOT sorted here. Sorting happens in
        _filter_indicators() after IOC length filtering and before
        checkpoint filtering.

        Args:
            data (Dict[str, Any]): Page data from saved result set API

        Returns:
            list[Dict[str, Any]]: List of filtered and deduplicated
                indicators (unsorted)
        """
        if not data:
            return []

        results = data.get("results", [])
        all_indicators = []
        for result in results:
            data_list = result.get("data", [])
            all_indicators.extend(data_list)

        indicators_list = [
            indicator
            for indicator in all_indicators
            if indicator.get("sdo_type", None) == "indicator"
        ]

        deduplicated_indicators = self._deduplicate_indicators(indicators_list)

        if deduplicated_indicators and len(indicators_list) != len(
            deduplicated_indicators
        ):
            removed = len(indicators_list) - len(deduplicated_indicators)
            utils.cloud_logging(
                f"Deduplicated page data: "
                f"{len(deduplicated_indicators)} unique indicators "
                f"(removed {removed} duplicates)"
            )

        return deduplicated_indicators

    def _ingest_indicators(
        self,
        indicators: list[Dict[str, Any]],
        from_timestamp: int,
        to_timestamp: int,
        page: int,
        chunk_info: str = "",
    ) -> int:
        """Common method to ingest indicators into Google SecOps.

        Args:
            indicators (list): List of indicators to ingest
            from_timestamp (int): From timestamp for checkpoint on error
            to_timestamp (int): To timestamp for checkpoint on error
            page (int): Current page number for checkpoint on error
            chunk_info (str): Optional chunk information for logging

        Returns:
            int: Count of indicators ingested

        Raises:
            Exception: If ingestion fails after saving checkpoint
        """
        if not indicators:
            return 0

        last_run_initiation_time = utility.get_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_LAST_RUN_INITIATION_TIME,
        )

        if last_run_initiation_time:
            try:
                last_run_time = float(last_run_initiation_time)
                current_time = time.time()
                time_diff_minutes = (current_time - last_run_time) / 60

                if time_diff_minutes >= constant.INGESTION_TIME_CHECK_MINUTES:
                    utils.cloud_logging(
                        f"Execution time has exceeded "
                        f"{constant.INGESTION_TIME_CHECK_MINUTES} minutes "
                        f"(running for {time_diff_minutes:.2f} minutes). "
                        f"Raising RunTimeExceeded exception.",
                        severity="WARNING",
                    )
                    raise exception_handler.RunTimeExceeded(
                        f"Execution time exceeded "
                        f"{constant.INGESTION_TIME_CHECK_MINUTES} minutes"
                    )
            except (ValueError, TypeError) as e:
                utils.cloud_logging(
                    f"Error checking execution time: {repr(e)}. "
                    f"Continuing with ingestion.\n"
                    f"Traceback: {traceback.format_exc()}",
                    severity="WARNING",
                )

        log_prefix = f"{chunk_info}: " if chunk_info else ""
        try:
            utils.cloud_logging(
                f"{log_prefix}Ingesting {len(indicators)} indicators "
                f"into Google SecOps."
            )
            ingest_v1.ingest(indicators, constant.GOOGLE_SECOPS_DATA_TYPE)
            utils.cloud_logging(
                f"{log_prefix}Successfully ingested {len(indicators)} "
                f"indicators."
            )
            return len(indicators)
        except Exception as e:
            utils.cloud_logging(
                f"{log_prefix}Ingestion failed: {repr(e)}\n"
                f"Traceback: {traceback.format_exc()}",
                severity="ERROR",
            )
            self._save_error_checkpoint(from_timestamp, to_timestamp, page, e)
            raise

    def _ingest_without_enrichment(
        self,
        indicators_list: list[Dict[str, Any]],
        from_timestamp: int,
        to_timestamp: int,
        page: int,
    ) -> int:
        """Ingest indicators without enrichment.

        Args:
            indicators_list (list): List of indicators to ingest
            from_timestamp (int): From timestamp for checkpoint on error
            to_timestamp (int): To timestamp for checkpoint on error
            page (int): Current page number for checkpoint on error

        Returns:
            int: Count of indicators ingested
        """
        for indicator in indicators_list:
            indicator["tenant_name"] = self.tenant_name

        try:
            ingested_count = self._ingest_indicators(
                indicators_list, from_timestamp, to_timestamp, page
            )
            return ingested_count
        except exception_handler.RunTimeExceeded as e:
            utils.cloud_logging(
                f"RunTimeExceeded during ingestion: {repr(e)}\n"
                f"Traceback: {traceback.format_exc()}",
                severity="WARNING",
            )
            self._save_error_checkpoint(from_timestamp, to_timestamp, page, e)
            raise

    def _process_enrichment_chunk(
        self,
        batch_idx: int,
        indicator_batch: list[Dict[str, Any]],
        checkpoint_value: int,
        from_timestamp: int,
        to_timestamp: int,
        page: int,
    ) -> int:
        """Process a single batch: fetch enrichment, merge, and ingest.

        Args:
            batch_idx (int): Current batch index (0-based)
            indicator_batch (list): Indicator objects in this batch
            checkpoint_value (int): Pre-determined ctix_modified checkpoint
                value
            from_timestamp (int): From timestamp for checkpoint on error
            to_timestamp (int): To timestamp for checkpoint on error
            page (int): Current page number for checkpoint on error

        Returns:
            int: Count of indicators ingested for this batch
        """
        if not indicator_batch:
            return 0

        ioc_values = [
            ind.get("sdo_name")
            for ind in indicator_batch
            if ind.get("sdo_name")
        ]
        if not ioc_values:
            utils.cloud_logging(
                f"Batch {batch_idx + 1}: No valid IOC values to enrich.",
                severity="WARNING",
            )
            return 0

        url = f"{self.base_url}/{constant.BULK_IOC_LOOKUP_ENDPOINT}"
        params = {
            "enrichment_data": constant.FETCH_ENRICHMENT_DATA,
            "relation_data": constant.FETCH_RELATION_DATA,
            "fields": ",".join(constant.ENRICHMENT_FIELDS),
            "page": 1,
            "page_size": constant.PAGE_SIZE_FOR_BULK_IOC,
        }
        json_body = {"value": ioc_values}

        try:
            response = self.make_api_call(
                "POST",
                url,
                params=params,
                json_body=json_body,
                fetch_type="Enrichment Data",
            )

            if not response.get("status"):
                error_message = (
                    f"Failed to fetch enrichment data for batch {batch_idx + 1}"
                    f"containing {len(ioc_values)} IOC(s) on page {page}. "
                    f"Error: {response.get('error')}"
                )
                utils.cloud_logging(error_message, severity="ERROR")
                raise exception_handler.CywareCTIXException(error_message)

            data = response.get("data", {})
            results = data.get("results", [])

            enrichment_map = {}
            for result in results:
                sdo_name = result.get("name")
                if sdo_name:
                    enrichment_map[sdo_name] = {
                        field: result.get(field)
                        for field in constant.ENRICHMENT_FIELDS
                        if field != "name" and result.get(field)
                    }

            utils.cloud_logging(
                f"Batch {batch_idx + 1}: enriched {len(enrichment_map)} "
                f"indicators."
            )

            batch_to_ingest = []
            for indicator in indicator_batch:
                indicator["tenant_name"] = self.tenant_name
                sdo_name = indicator.get("sdo_name")
                if sdo_name and sdo_name in enrichment_map:
                    indicator.update(enrichment_map[sdo_name])
                batch_to_ingest.append(indicator)

            ingested_count = self._ingest_indicators(
                batch_to_ingest,
                from_timestamp,
                to_timestamp,
                page,
                chunk_info=f"Batch {batch_idx + 1}",
            )

            if checkpoint_value and checkpoint_value > 0:
                utility.set_last_checkpoint(
                    self.tenant_name,
                    self.bucket_name,
                    constant.CHECKPOINT_KEY_CTIX_MODIFIED,
                    checkpoint_value,
                )
                utils.cloud_logging(
                    f"Saved checkpoint: ctix_modified = {checkpoint_value}"
                )

            return ingested_count

        except exception_handler.RunTimeExceeded as e:
            utils.cloud_logging(
                f"RunTimeExceeded during enrichment batch processing: "
                f"{repr(e)}\n"
                f"Traceback: {traceback.format_exc()}",
                severity="WARNING",
            )
            self._save_error_checkpoint(from_timestamp, to_timestamp, page, e)
            raise
        except Exception as e:
            utils.cloud_logging(
                f"Exception during enrichment batch processing: {repr(e)}\n"
                f"Traceback: {traceback.format_exc()}",
                severity="ERROR",
            )
            self._save_error_checkpoint(from_timestamp, to_timestamp, page, e)
            raise

    def _filter_indicators(
        self, indicators_list: list[Dict[str, Any]]
    ) -> list[Dict[str, Any]]:
        """Filter out indicators with IOC values exceeding max length, sort by
        ctix_modified, and filter based on checkpoint.

        Args:
            indicators_list (list): List of indicator dictionaries

        Returns:
            list: Filtered and sorted list of indicators
        """
        if not indicators_list:
            return []

        max_ioc_length = constant.MAX_IOC_LENGTH_FOR_BULK_LOOKUP
        filtered_indicators = []
        skipped_count = 0

        for indicator in indicators_list:
            sdo_name = indicator.get("sdo_name", "")
            if sdo_name and len(sdo_name) <= max_ioc_length:
                filtered_indicators.append(indicator)
            else:
                skipped_count += 1

        if skipped_count > 0:
            utils.cloud_logging(
                f"Filtered out {skipped_count} indicator(s) with IOC "
                f"length > {max_ioc_length}",
                severity="WARNING",
            )

        sorted_indicators = sorted(
            filtered_indicators, key=lambda x: x.get("ctix_modified", 0)
        )
        utils.cloud_logging(
            f"Sorted {len(sorted_indicators)} indicators by "
            f"ctix_modified in ascending order."
        )

        checkpoint_keys = [
            constant.CHECKPOINT_KEY_FROM_TIMESTAMP,
            constant.CHECKPOINT_KEY_TO_TIMESTAMP,
            constant.CHECKPOINT_KEY_PAGE_NUMBER,
            constant.CHECKPOINT_KEY_CTIX_MODIFIED,
        ]

        checkpoints = {
            key: utility.get_last_checkpoint(
                self.tenant_name, self.bucket_name, key
            )
            for key in checkpoint_keys
        }

        if all(checkpoints.values()):
            last_ctix_modified_int = int(
                checkpoints[constant.CHECKPOINT_KEY_CTIX_MODIFIED]
            )
            checkpoint_filtered = [
                ind
                for ind in sorted_indicators
                if ind.get("ctix_modified", 0) >= last_ctix_modified_int
            ]
            removed_count = len(sorted_indicators) - len(checkpoint_filtered)
            if removed_count > 0:
                utils.cloud_logging(
                    f"Filtered out {removed_count} indicator(s) with "
                    f"ctix_modified < {last_ctix_modified_int} based on "
                    f"checkpoint (mid-ingestion resume detected).",
                    severity="INFO",
                )
            return checkpoint_filtered

        return sorted_indicators

    def _enrich_and_ingest_by_chunks(
        self,
        indicators_list: list[Dict[str, Any]],
        from_timestamp: int,
        to_timestamp: int,
        page: int,
    ) -> int:
        """Process indicators in batches, enriching and ingesting each batch.

        Args:
            indicators_list (list): List of indicators to process
            from_timestamp (int): From timestamp for checkpoint on error
            to_timestamp (int): To timestamp for checkpoint on error
            page (int): Current page number for checkpoint on error

        Returns:
            int: Total count of indicators ingested

        Raises:
            Exception: If enrichment or ingestion fails
        """
        if not indicators_list:
            utils.cloud_logging("No indicators to process.", severity="WARNING")
            return 0

        if not self.enrichment_enabled:
            utils.cloud_logging("Enrichment is disabled.")
            return self._ingest_without_enrichment(
                indicators_list, from_timestamp, to_timestamp, page
            )

        utils.cloud_logging(
            "Enrichment is enabled. Processing indicators in batches."
        )

        filtered_indicators = self._filter_indicators(indicators_list)
        if not filtered_indicators:
            utils.cloud_logging("No indicators remaining after filtering.")
            return 0

        batch_size = constant.MAX_BULK_IOC_BATCH_SIZE
        total_batches = (
            len(filtered_indicators) + batch_size - 1
        ) // batch_size

        utils.cloud_logging(
            f"Processing {len(filtered_indicators)} indicators in "
            f"{total_batches} batch(es) of {batch_size}."
        )

        total_ingested = 0
        for batch_idx in range(total_batches):
            start_idx = batch_idx * batch_size
            end_idx = min(start_idx + batch_size, len(filtered_indicators))
            indicator_batch = filtered_indicators[start_idx:end_idx]

            checkpoint_value = indicator_batch[-1].get("ctix_modified")

            batch_count = self._process_enrichment_chunk(
                batch_idx,
                indicator_batch,
                checkpoint_value,
                from_timestamp,
                to_timestamp,
                page,
            )
            total_ingested += batch_count

        return total_ingested

    def _save_error_checkpoint(
        self,
        from_timestamp: int,
        to_timestamp: int,
        page: int,
        error: Exception,
    ) -> None:
        """Save checkpoint on ingestion error.

        Args:
            from_timestamp (int): Original from_timestamp to resume from
            to_timestamp (int): Original to_timestamp used in the API call
            page (int): Current page number
            error (Exception): The exception that occurred
        """
        utils.cloud_logging(
            f"Error ingesting indicators for page {page}: {repr(error)}\n"
            f"Traceback: {''.join(traceback.format_exception(type(error), error, error.__traceback__))}",
            severity="ERROR",
        )
        utility.set_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_FROM_TIMESTAMP,
            from_timestamp,
        )
        utility.set_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_TO_TIMESTAMP,
            to_timestamp,
        )
        utility.set_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_PAGE_NUMBER,
            page,
        )

    def fetch_indicators_by_labels(self) -> None:
        """Universal entry point for indicator ingestion.

        Handles both single-label and multi-label ingestion with checkpoint-based
        resume logic.

        Single Label:
            - Directly calls fetch_indicator_data() for the single label

        Multi-Label Case 1 (First-time execution):
            - Reads comma-separated label list
            - Saves label list to checkpoint
            - Calculates from/to timestamps ONCE for all labels
            - Iterates through each label, updating current_label checkpoint
            - Calls fetch_indicator_data() for each label with same timestamps
            - Clears label checkpoints after successful completion

        Multi-Label Case 2 (Resume after failure):
            - Compares saved label list with new label list
            - If different: treats as fresh run (Case 1)
            - If same: resumes from last active label
            - Removes already-processed labels from the list
            - Continues ingestion from the current label
        """
        current_label_list = self.label_name
        if not current_label_list:
            utils.cloud_logging(
                "No saved result set list provided. Skipping ingestion.",
                severity="WARNING",
            )
            return

        labels_to_process = [
            label.strip()
            for label in current_label_list.split(",")
            if label.strip()
        ]

        if not labels_to_process:
            utils.cloud_logging(
                "Saved result set list is empty after parsing. Skipping ingestion.",
                severity="WARNING",
            )
            return

        saved_label_list = utility.get_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_LABEL_LIST,
        )
        saved_current_label = utility.get_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_CURRENT_LABEL,
        )

        utils.cloud_logging(
            f"Parsed {len(labels_to_process)} saved result set(s) from input: "
            f"{labels_to_process}",
            severity="INFO",
        )

        if saved_label_list != current_label_list:
            utils.cloud_logging(
                f"Saved result set list in checkpoint: {saved_label_list}, "
                f"from input:{current_label_list}. Starting "
                "fresh ingestion run.",
                severity="DEBUG",
            )
            self._clear_label_error_checkpoints()
        else:
            if (
                saved_current_label in labels_to_process
                or saved_current_label is None
            ):
                if saved_current_label is None:
                    current_label_index = 0
                else:
                    current_label_index = labels_to_process.index(
                        saved_current_label
                    )
                utils.cloud_logging(
                    f"Resuming ingestion from label: {labels_to_process[current_label_index]}",
                    severity="INFO",
                )
                labels_to_process = labels_to_process[current_label_index:]
                utils.cloud_logging(
                    f"Resuming with {len(labels_to_process)} remaining "
                    f"saved result set(s): {labels_to_process}",
                    severity="INFO",
                )
            else:
                utils.cloud_logging(
                    f"Saved current tag '{saved_current_label}' not found "
                    f"in new saved result set list. Starting fresh.",
                    severity="WARNING",
                )
                self._clear_label_error_checkpoints()

        from_timestamp, to_timestamp, _ = self._get_checkpoints_and_timestamps()
        utils.cloud_logging(
            f"Using from_timestamp={from_timestamp}, to_timestamp={to_timestamp} "
            f"for {len(labels_to_process)} label(s).",
            severity="INFO",
        )
        utility.set_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_LABEL_LIST,
            current_label_list,
        )
        utils.cloud_logging(
            f"Saved label list to checkpoint: {current_label_list}",
            severity="DEBUG",
        )

        for label in labels_to_process:
            utils.cloud_logging(f"Processing label: '{label}'", severity="INFO")

            utility.set_last_checkpoint(
                self.tenant_name,
                self.bucket_name,
                constant.CHECKPOINT_KEY_CURRENT_LABEL,
                label,
            )
            utils.cloud_logging(
                f"Updated current_label checkpoint to: '{label}'",
                severity="DEBUG",
            )

            self.label_name = label

            try:
                self.fetch_indicator_data(
                    from_timestamp=from_timestamp, to_timestamp=to_timestamp
                )
                utils.cloud_logging(
                    f"Successfully completed ingestion for label: '{label}'",
                    severity="INFO",
                )
            except exception_handler.RunTimeExceeded as e:
                utils.cloud_logging(
                    f"RunTimeExceeded while processing label '{label}'. "
                    f"Checkpoint saved for resume. Error: {repr(e)}\n"
                    f"Traceback: {traceback.format_exc()}",
                    severity="WARNING",
                )
                raise
            except Exception as e:
                utils.cloud_logging(
                    f"Error processing label '{label}': {repr(e)}\n"
                    f"Traceback: {traceback.format_exc()}",
                    severity="ERROR",
                )
                raise

        utility.set_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_FROM_TIMESTAMP,
            to_timestamp,
        )
        utility.clear_checkpoint_if_exists(
            constant.CHECKPOINT_KEY_TO_TIMESTAMP,
            "to_timestamp",
            self.tenant_name,
            self.bucket_name,
        )
        utils.cloud_logging(
            f"Updated from_timestamp to {to_timestamp} for next run. "
            "Cleared to_timestamp.",
            severity="INFO",
        )

        utility.clear_checkpoint_if_exists(
            constant.CHECKPOINT_KEY_CURRENT_LABEL,
            "current_label",
            self.tenant_name,
            self.bucket_name,
        )
        utils.cloud_logging(
            "All labels processed successfully. Cleared label checkpoints.",
            severity="INFO",
        )

    def _clear_label_error_checkpoints(self) -> None:
        """Clear label-related checkpoints after successful completion."""
        utility.clear_checkpoint_if_exists(
            constant.CHECKPOINT_KEY_LABEL_LIST,
            "label_list",
            self.tenant_name,
            self.bucket_name,
        )
        utility.clear_checkpoint_if_exists(
            constant.CHECKPOINT_KEY_CURRENT_LABEL,
            "current_label",
            self.tenant_name,
            self.bucket_name,
        )
        utility.clear_checkpoint_if_exists(
            constant.CHECKPOINT_KEY_FROM_TIMESTAMP,
            "from_timestamp",
            self.tenant_name,
            self.bucket_name,
        )
        utility.clear_checkpoint_if_exists(
            constant.CHECKPOINT_KEY_TO_TIMESTAMP,
            "to_timestamp",
            self.tenant_name,
            self.bucket_name,
        )
        utility.clear_checkpoint_if_exists(
            constant.CHECKPOINT_KEY_CTIX_MODIFIED,
            "ctix_modified",
            self.tenant_name,
            self.bucket_name,
        )
        utility.clear_checkpoint_if_exists(
            constant.CHECKPOINT_KEY_PAGE_NUMBER,
            "page_number",
            self.tenant_name,
            self.bucket_name,
        )

    def fetch_indicator_data(
        self, from_timestamp: int, to_timestamp: int
    ) -> None:
        """Prepare complete indicator data response from CTIX.

        Fetches saved result set data page by page with enrichment
        data (if enabled), merges enrichment relations into indicators,
        adds tenant_name to each, and ingests them. Manages checkpoints
        for resumability.

        Args:
            from_timestamp: Start timestamp for data fetch (mandatory).
            to_timestamp: End timestamp for data fetch (mandatory).

        This function is called from fetch_indicators_by_labels() which
        calculates the timestamps once for all labels.
        """
        utils.cloud_logging("Fetching indicator data from CTIX.")

        last_page_number = utility.get_last_checkpoint(
            self.tenant_name,
            self.bucket_name,
            constant.CHECKPOINT_KEY_PAGE_NUMBER,
        )
        if last_page_number:
            try:
                page = int(last_page_number)
                utils.cloud_logging(
                    f"Resuming from page {page}", severity="INFO"
                )
            except (ValueError, TypeError):
                page = 1
        else:
            page = 1

        utils.cloud_logging(
            f"Using timestamps: from={from_timestamp}, to={to_timestamp}",
            severity="INFO",
        )
        total_indicators_processed = 0

        while True:
            try:
                utils.cloud_logging(
                    f"Fetching saved result set page {page} with page_size "
                    f"{constant.PAGE_SIZE_FOR_SAVED_RESULT}"
                )

                data = self.get_saved_result_set_page(
                    from_timestamp, to_timestamp, page
                )

                indicators_list = self._extract_indicators_from_page_data(data)

                if not indicators_list:
                    utils.cloud_logging(f"No indicators found on page {page}.")
                    if not data.get("next"):
                        break
                    page += 1
                    continue

                utils.cloud_logging(
                    f"Page {page}: found {len(indicators_list)} indicators."
                )

                page_ingested_count = self._enrich_and_ingest_by_chunks(
                    indicators_list, from_timestamp, to_timestamp, page
                )
                total_indicators_processed += page_ingested_count

                utility.clear_checkpoint_if_exists(
                    constant.CHECKPOINT_KEY_CTIX_MODIFIED,
                    "ctix_modified",
                    self.tenant_name,
                    self.bucket_name,
                )
                utility.set_last_checkpoint(
                    self.tenant_name,
                    self.bucket_name,
                    constant.CHECKPOINT_KEY_PAGE_NUMBER,
                    page,
                )

                if not data.get("next"):
                    utils.cloud_logging(
                        f"Reached last page {page}. All data processed."
                    )
                    break

                page += 1

            except exception_handler.RunTimeExceeded as e:
                utils.cloud_logging(
                    f"RunTimeExceeded exception caught in fetch_indicator_data."
                    f"Total indicators processed: {total_indicators_processed}\n"
                    f"Traceback: {traceback.format_exc()}",
                    severity="WARNING",
                )
                self._save_error_checkpoint(
                    from_timestamp, to_timestamp, page, e
                )
                raise
            except Exception as e:
                utils.cloud_logging(
                    f"Exception in fetch_indicator_data: {repr(e)}\n"
                    f"Traceback: {traceback.format_exc()}",
                    severity="ERROR",
                )
                self._save_error_checkpoint(
                    from_timestamp, to_timestamp, page, e
                )
                raise

        utility.clear_checkpoint_if_exists(
            constant.CHECKPOINT_KEY_PAGE_NUMBER,
            "page_number",
            self.tenant_name,
            self.bucket_name,
        )

        utils.cloud_logging(
            f"Completed ingestion for current label: {self.label_name}. Total indicators processed: "
            f"{total_indicators_processed}"
        )

    def extract_ioc_values(
        self, indicators_data: list[Dict[str, Any]]
    ) -> list[str]:
        """Extract IOC values from indicators data for bulk lookup.

        Args:
            indicators_data: List of indicator dictionaries

        Returns:
            List of unique IOC values (names)
        """
        if not indicators_data:
            return []

        ioc_values = set()
        for indicator in indicators_data:
            ioc_value = indicator.get("sdo_name", "")
            if ioc_value:
                ioc_values.add(ioc_value)
        return list(ioc_values)

    def get_start_time(self, lookback_days: str = None) -> int:
        """Get start time as epoch timestamp based on lookback days.

        Args:
            lookback_days: Number of days to look back
                (as string from env variable)

        Returns:
            int: Epoch timestamp for the start time
        """
        if lookback_days:
            try:
                days = int(lookback_days)
                if days < 0:
                    raise ValueError(
                        f"lookback_days must be non-negative, got {days}"
                    )
                start_time = datetime.datetime.now(
                    datetime.timezone.utc
                ) - datetime.timedelta(days=days)
                epoch_time = int(start_time.timestamp())
                start_time_str = start_time.strftime(constant.TIMESTAMP_PATTERN)
                utils.cloud_logging(
                    f"Calculated start time from lookback_days ({days}): "
                    f"{start_time_str}"
                )
                return epoch_time
            except (ValueError, TypeError) as e:
                default_days = constant.DEFAULT_VALUES.get(
                    constant.ENV_INDICATOR_LOOKBACK_DAYS, 7
                )
                utils.cloud_logging(
                    f"Error parsing lookback_days '{lookback_days}': {e}. "
                    f"Using default {default_days} days.",
                    severity="WARNING",
                )

        default_days = constant.DEFAULT_VALUES.get(
            constant.ENV_INDICATOR_LOOKBACK_DAYS, 7
        )
        start_time = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(days=default_days)
        epoch_time = int(start_time.timestamp())
        start_time_str = start_time.strftime(constant.TIMESTAMP_PATTERN)
        utils.cloud_logging(
            f"Using default lookback of {default_days} days, "
            f"Calculated start time : {start_time_str}"
        )
        return epoch_time
