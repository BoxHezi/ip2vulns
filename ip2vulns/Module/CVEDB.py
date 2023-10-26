from pathlib import Path
from tinydb import TinyDB, Query

from .. import utils

class CVE:
    def __init__(self, data: dict):
        vars(self).update(data)

    def get_score(self):
        return vars(self)["score"]


class CVEDB:
    def __init__(self, db_file = "cve_db.json", db_path = str(Path.home()) + "/.config/ip2vulns/", table_name = "cve"):
        utils.create_path(db_path)
        self.db = TinyDB(db_path + db_file)
        self.table = self.db.table(table_name)

    def upsert(self, data: CVE, table = None):
        if table is None:
            table = self.table
        cve = Query()
        table.upsert(vars(data), cve.id == vars(data)["id"])

    def get_cve_by_id(self, cve_id, table = None):
        if table is None:
            table = self.table
        cve = Query()
        records = table.search(cve.id.matches(cve_id))

        if len(records) == 0:
            return None
        return CVE(records[0])

    def get_cvss_score_by_cve(self, cve: CVE):
        return cve.get_score()