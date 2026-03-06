# Cyware Intel Exchange Resources for Google SecOps SIEM Integration

## Dashboards

You can visualize and analyze ingested data by creating dashboards in Google SecOps SIEM.

### Import a Native Dashboard into Google SecOps SIEM

Complete the following steps to import a dashboard:

1. Download the dashboard `.json` files for Cyware Intel Exchange from the following [GitHub](https://github.com/cyware-labs/google-secops/tree/develop/siem/Dashboards) repository.
2. From Google SecOps SIEM, Go to **Dashboards & Reports** > **Dashboards**, Select **New Dashboard** > **Import from JSON**.
3. Click on **Upload Dashboard files** dialog, browse and select the appropriate JSON file.
4. Click **Edit** to update the name, description, and the dashboard access you're importing.
5. Click **Import** to import the dashboard.

See [Import Dashboards into Google SecOps](https://cloud.google.com/chronicle/docs/reports/manage-native-dashboards#import-dashboards) for more information.


## Create Correlation Rules for Detections and Alerts

Correlation rules scan events ingested into Google SecOps SIEM to generate detections and alerts for specified anomalies.  provides seven rules that you can modify or copy to get started. You can find the Cyware Intel Exchange correlation rules in the following [GitHub](https://github.com/cyware-labs/google-secops/tree/develop/siem/Detection%20Rules) repository.

### Create a New Correlation Rule

1. From Google SecOps SIEM, navigate to **Detections > Rules & Detections**.
2. From the **Rules Editor** tab, click **New**.
3. In the rule editor, clear all the contents, and then copy and paste the code from the [GitHub](https://github.com/cyware-labs/google-secops/tree/develop/siem/Detection%20Rules) repository.
4. Click **Save New Rule**.
5. To generate alerts from the correlation rule, click the three dots next to the rule name and enable the **Alerting** option.

See [Manage rules using Rules Editor](https://cloud.google.com/chronicle/docs/detection/manage-all-rules#:~:text=Click%20New%20in,click%20DISCARD.) for more information.

---

For more information, please refer the User guide.