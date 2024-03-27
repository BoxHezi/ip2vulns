import json

class CVE:
    def __init__(self, **kwargs) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)

    def get_id(self):
        return vars(self).get("id")

    def get_cvss_score(self):
        version = ""
        score = 0
        severity = "None"
        if "cvssMetricV31" in self.metrics:
            version = "V31"
            score = self.metrics.get("cvssMetricV31")[0].get("cvssData").get("baseScore")
            severity = self.metrics.get("cvssMetricV31")[0].get("cvssData").get("baseSeverity")
        elif "cvssMetricV30" in self.metrics:
            version = "V30"
            score = self.metrics.get("cvssMetricV30")[0].get("cvssData").get("baseScore")
            severity = self.metrics.get("cvssMetricV30")[0].get("cvssData").get("baseSeverity")
        elif "cvssMetricV2" in self.metrics:
            version = "V2"
            score = self.metrics.get("cvssMetricV2")[0].get("cvssData").get("baseScore")
            severity = self.metrics.get("cvssMetricV2")[0].get("baseSeverity")

        return [version, score, severity]

    def __repr__(self):
        return json.dumps(vars(self), indent=4)
