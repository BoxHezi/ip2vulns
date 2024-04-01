from .. import utils


class InternetDB:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.ip_int = utils.ip_int(self.ip)
        self.last_updated = utils.get_now_datetime()

    def __repr__(self):
        out = [f"\nIP: {self.ip}"]
        if self.hostnames:
            out.extend(["\nHostnames:", *(f"\t{name}" for name in self.hostnames)])
        if self.ports:
            out.extend(["\nPorts:", *(f"\t{port}" for port in self.ports)])
        if self.vulns:
            out.extend(["\nVulns:", *(f"\t{vuln}" for vuln in self.vulns)])
        return '\n'.join(out) + "\n"

    def __str__(self):
        # re-order keys of attribute
        attribute_order = ["ip_int", "ip", "hostnames", "ports", "cpes", "vulns", "tags", "last_updated"]
        out_dict = {k: getattr(self, k) for k in attribute_order}
        out_dict.update({"last_updated": utils.datetime_2_str(out_dict.get("last_updated"))})

        out = []
        for k, v in out_dict.items():
            if not k.startswith("_"):
                if isinstance(v, list):
                    v = "|".join([str(i) for i in v])
                out.append(str(v))
        return ",".join(out)

