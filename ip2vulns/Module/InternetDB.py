from sqlalchemy import Integer, String, DateTime
from sqlalchemy import Column
from sqlalchemy.orm import declarative_base

from .DatabaseDriver import Database
from .. import utils


class InternetDB(declarative_base()):
    __tablename__ = "internetdb"
    ip = Column(Integer, primary_key=True, index=True)
    ip_str = Column(String, nullable=False)
    hostnames = Column(String)
    ports = Column(String)
    cpes = Column(String)
    vulns = Column(String)
    tags = Column(String)
    last_updated = Column(DateTime, default=utils.get_now_datetime(), onupdate=utils.get_now_datetime())

    def __init__(self, data):
        self.ip = utils.ip_int(data["ip"])
        self.ip_str = data["ip"]
        self.hostnames = data["hostnames"]
        self.ports = data["ports"]
        self.cpes = data["cpes"]
        self.vulns = data["vulns"]
        self.tags = data["tags"]

    def __repr__(self):
        out = f"IP: {self.ip_str}\n"
        out += f"Hostnames: {self.hostnames}\n"
        out += f"Ports: {self.ports}\n"
        out += f"vulns: {self.vulns}\n"
        return out

    def __str__(self):
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


class InternetDBDAO:
    def __init__(self, db: Database):
        self.db = db

    def add_record(self, record: InternetDB):
        session = self.db.get_session()
        session.add(record)

    def update_record(self, new: InternetDB):
        session = self.db.get_session()
        record = session.query(InternetDB).filter(InternetDB.ip == new.ip).all()[0]
        record.hostnames = new.hostnames
        record.ports = new.ports
        record.cpes = new.cpes
        record.vulns = new.vulns
        record.tags = new.tags
        record.last_updated = utils.get_now_datetime()

    def get_all_records(self):
        session = self.db.get_session()
        records = session.query(InternetDB).all()
        return records

    def get_all_records_has_vulns(self):
        session = self.db.get_session()
        records = session.query(InternetDB).filter(InternetDB.vulns != '').all()
        return records

    def get_record_by_ip(self, ip: int | str):
        if isinstance(ip, str):
            ip = utils.ip_int(ip)
        session = self.db.get_session()
        record = session.query(InternetDB).filter(InternetDB.ip == ip).all()
        if len(record) == 0:
            print(f"No record matched for {utils.ip_str(ip)} founded")
        else:
            return record[0]

    def has_record_for_ip(self, ip: int | str):
        if isinstance(ip, str):
            ip = utils.ip_int(ip)
        session = self.db.get_session()
        record = session.query(InternetDB).filter(InternetDB.ip == ip)
        return session.query(record.exists()).scalar()
