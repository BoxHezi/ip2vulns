from .. import utils


class InternetDB():
    def __init__(self, data):
        self.ip = utils.ip_int(data["ip"])
        self.ip_str = data["ip"]
        self.hostnames = data["hostnames"]
        self.ports = data["ports"]
        self.cpes = data["cpes"]
        self.vulns = data["vulns"]
        self.tags = data["tags"]
        self.last_updated = utils.get_now_datetime()

    def __repr__(self):
        out = f"IP: {self.ip_str}\n"
        out += f"Hostnames: {self.hostnames}\n"
        out += f"Ports: {self.ports}\n"
        out += f"vulns: {self.vulns}\n"
        return out

    def __str__(self):
        self.last_updated = utils.datetime_2_str(self.last_updated)
        out = []
        for k, v in vars(self).items():
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


