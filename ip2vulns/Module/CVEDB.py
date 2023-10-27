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
        """
        Inserts a new record or updates an existing record in the database
        :param data: An instance of the CVE class
        :param table: The table in which to perform the operation. Defaults to self.table
        """
        if table is None:
            table = self.table
        cve = Query()
        table.upsert(vars(data), cve.id == vars(data)["id"])

    def get_cve_by_id(self, cve_id, table = None):
        """
        Retrieves a CVE record from the database using a given CVE ID
        :param cve_id: CVE ID to search for, CVE-YYYY-XXXX
        :param table: The table in which to perform the operation. Defaults to self.table
        :return: A CVE object created from the matching record, or None if no matching record is found
        """
        if table is None:
            table = self.table
        cve = Query()
        records = table.search(cve.id.matches(cve_id))

        if len(records) == 0:
            return None
        return CVE(records[0])

    def get_cvss_score_by_cve(self, cve: CVE):
        return cve.get_score()

    def close(self):
        self.db.close()