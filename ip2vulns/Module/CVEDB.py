from pathlib import Path
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware

from .. import utils

class CVE:
    def __init__(self, data: dict):
        vars(self).update(data)

    def get_attribute(self, attribute: str):
        """
        get attributes for the CVE instance
        :param attribute: attribute value to retrieve
        :return: value corresponding to the attribute, None if no such attribute
        """
        value = vars(self)[attribute]
        return value if value else None


class CVEDB:
    def __init__(self, db_file = "cve_db.json", db_path = str(Path.home()) + "/.config/ip2vulns/", table_name = "cve"):
        utils.create_path(db_path)
        storage_path = db_path + db_file
        self.db = TinyDB(storage_path, storage=CachingMiddleware(JSONStorage))
        self.query = Query()
        self.table = self.db.table(table_name)

    def upsert(self, data: CVE, table = None):
        """
        Inserts a new record or updates an existing record in the database
        :param data: An instance of the CVE class
        :param table: The table in which to perform the operation. Defaults to self.table
        """
        if table is None:
            table = self.table
        table.upsert(vars(data), self.query.id == vars(data)["id"])

    def get_cve_by_id(self, cve_id, table = None):
        """
        Retrieves a CVE record from the database using a given CVE ID
        :param cve_id: CVE ID to search for, CVE-YYYY-XXXX
        :param table: The table in which to perform the operation. Defaults to self.table
        :return: A CVE object created from the matching record, or None if no matching record is found
        """
        if table is None:
            table = self.table
        records = table.search(self.query.id.matches(cve_id))

        return None if len(records) == 0 else CVE(records[0])

    def get_cvss_score_by_cve(self, cve: CVE):
        return cve.get_attribute("score")

    def flush(self):
        """
        flush cache to write data to disk
        """
        try:
            self.db.storage.flush()
        except Exception as e:
            print(f"Exception when flushing database: {self.db} - {e}")

    def close(self):
        """
        close database
        """
        try:
            self.db.close()
        except Exception as e:
            print(f"Exception when closing database: {self.db} - {e}")