import json

class CVE:
    def __init__(self, **kwargs) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)

    def get_id(self):
        return vars(self).get("id")

    def get_cvss_score(self):
        # result => [[version, score, severity], ...]
        result = [] # 2D array, contains cvssMetric different version accordingly

        temp = []
        if "cvssMetricV40" in self.metrics:
            for data in self.metrics.get("cvssMetricV40"):
                temp.append("V40")
                temp.append(data.get("cvssData").get("baseScore"))
                temp.append(data.get("cvssData").get("baseSeverity"))
                result.append(temp)

        if "cvssMetricV31" in self.metrics:
            for data in self.metrics.get("cvssMetricV31"):
                temp.append("V31")
                temp.append(data.get("cvssData").get("baseScore"))
                temp.append(data.get("cvssData").get("baseSeverity"))
                result.append(temp)

        if "cvssMetricV30" in self.metrics:
            for data in self.metrics.get("cvssMetricV30"):
                temp.append("V30")
                temp.append(data.get("cvssData").get("baseScore"))
                temp.append(data.get("cvssData").get("baseSeverity"))
                result.append(temp)

        if "cvssMetricV2" in self.metrics:
            for data in self.metrics.get("cvssMetricV2"):
                temp.append("V2")
                temp.append(data.get("cvssData").get("baseScore"))
                temp.append(data.get("baseSeverity"))
                result.append(temp)

        return result

    def __repr__(self):
        return json.dumps(vars(self), indent=4)
