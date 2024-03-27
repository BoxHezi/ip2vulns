from .. import utils


class InternetDB:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.ip_int = utils.ip_int(self.ip)
        self.last_updated = utils.get_now_datetime()

    def __repr__(self):
        out = f"IP: {self.ip_str}\n"
        out += f"Hostnames: {self.hostnames}\n"
        out += f"Ports: {self.ports}\n"
        out += f"vulns: {self.vulns}\n"
        return out

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

    def format_data_for_db(self):
        self.hostnames = utils.list_2_str(self.hostnames)
        self.ports = utils.list_2_str(self.ports)
        self.cpes = utils.list_2_str(self.cpes)
        self.vulns = utils.list_2_str(self.vulns)
        self.tags = utils.list_2_str(self.tags)


