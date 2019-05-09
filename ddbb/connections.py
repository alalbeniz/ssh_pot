"""Database connector"""
from peewee import *
import datetime
import os


dbg = False

APP_DIR = os.path.dirname(os.path.realpath(__file__))
if dbg: print(os.path.join(APP_DIR, 'database_connections.db'))
db = SqliteDatabase(os.path.join(APP_DIR, 'database_connections.db'))

class Blacklist(Model):
    id               = AutoField(primary_key=True)
    description      = CharField(max_length=50)

    class Meta:
        """Import db."""
        database = db


class Threat(Model):
    id               = AutoField(primary_key=True)
    description      = CharField(max_length=50)

    class Meta:
        """Import db."""
        database = db

IPBlacklistThroughDeferred = DeferredThroughModel()

IPThreatThroughDeferred = DeferredThroughModel()

class IP(Model):
#    id               = AutoField(primary_key=True)
    address          = CharField(max_length=15, primary_key=True)
    asn_organization = CharField(max_length=100, null=True)
    asn_number       = CharField(max_length=15, null=True)
    threat_level     = CharField(max_length=15, null=True)
    city             = CharField(max_length=50, null=True)
    region           = CharField(max_length=50, null=True)
    latitude         = DoubleField(null=True)
    longitude        = DoubleField(null=True)
    country          = CharField(max_length=50, null=True)
    iso_code         = CharField(max_length=2, null=True)
    postal_code      = CharField(max_length=50, null=True)
    blacklist_count  = IntegerField(null=True)
    blacklists       = ManyToManyField(Blacklist, through_model=IPBlacklistThroughDeferred)
    threat           = ManyToManyField(Threat, through_model=IPThreatThroughDeferred)

    class Meta:
        """Import db."""
        database = db

class IPBlacklist(Model):
    IP               = ForeignKeyField(IP)
    blacklist        = ForeignKeyField(Blacklist)

    class Meta:
        database = db
        primary_key = CompositeKey("IP", "blacklist")

class IPThreat(Model):
    IP               = ForeignKeyField(IP)
    threat           = ForeignKeyField(Threat)

    class Meta:
        database = db
        primary_key = CompositeKey("IP", "threat")


IPBlacklistThroughDeferred.set_model(IPBlacklist)
IPThreatThroughDeferred.set_model(IPThreat)


class Sample(Model):
    id          = AutoField(primary_key=True)
    name        = CharField(max_length=100)
    md5sum      = CharField(max_length=100, null=True)
    sha1sum     = CharField(max_length=100, null=True)
    sha256sum   = CharField(max_length=100, null=True)
    raw_result  = TextField(null=True)
    scan_result = IntegerField(null=True)
    vt_link     = CharField(max_length=500, null=True)
    positives   = IntegerField(null=True)
    total       = IntegerField(null=True)
    results     = CharField(max_length=1000, null=True)
    timestamp   = DateTimeField(default=datetime.datetime.now)

    class Meta:
        database = db


ConnectionSampleThroughDeferred = DeferredThroughModel()


class Connection(Model):
    id          = AutoField(primary_key=True)
    username    = CharField(max_length=100)
    password    = CharField(max_length=100)
    timestamp   = DateTimeField(default=datetime.datetime.now)
    ip          = ForeignKeyField(IP, null=True)
    command     = CharField(max_length=1000, null=True)
    remote_version  = CharField(max_length=100, null=True)
    sample          = ManyToManyField(Sample, through_model=ConnectionSampleThroughDeferred)

    class Meta:
        """Import db."""
        database = db


class ConnectionSample(Model):
    connection   = ForeignKeyField(Connection)
    sample       = ForeignKeyField(Sample)

    class Meta:
        database = db
        primary_key = CompositeKey("connection", "sample")


ConnectionSampleThroughDeferred.set_model(ConnectionSample)


db.connect()
db.create_tables([Connection,IP, IPThreat, IPBlacklist, Threat, Blacklist, Sample], safe=True)
if dbg: print("DB created")
db.commit()

@db.atomic()
def add_connection(username, password, address=None, command=None, remote_version=None):
    ip = None
    if address:
        ip = IP.get_or_create(address=address)
#        Connection.create(username=username, password=password, ip=ip).save()
#    else:
    return Connection.create(username=username, password=password, ip=ip, command=command, remote_version=remote_version).save()

@db.atomic()
def get_connection(username):
    return Connection.get(Connection.username == username)

@db.atomic()
def add_IP(username, password):
    Connection.create(username=username, password=password).save()

@db.atomic()
def get_IP(address):
    return IP.get(IP.address == address)

@db.atomic()
def add_threat(description):
    Threat.create(description=description).save()

@db.atomic()
def get_threat(description):
    return Threat.get(Threat.description == description)

@db.atomic()
def add_blacklist(description):
    Blacklist.create(description=description).save()

@db.atomic()
def get_blacklist(description):
    return Blacklist.get(Blacklist.description == description)

@db.atomic()
def add_sample(name, url=None):
    Sample.create(name=name, url=url).save()

@db.atomic()
def add_sample_connection(connection, sample):
    ConnectionSample.create(connection=connection, sample=sample).save()

