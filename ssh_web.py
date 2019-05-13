#!/usr/bin/env python3
import os
import json

from flask import (Flask, render_template)
from peewee import fn, SQL, JOIN

from playhouse.flask_utils import get_object_or_404

from ddbb.connections import Connection, IP, Sample

APP_DIR = os.path.dirname(os.path.realpath(__file__))

# The playhouse.flask_utils.FlaskDB object accepts database URL configuration.
DATABASE = 'sqliteext:///%s' % os.path.join(APP_DIR, 'ddbb/database_connections.db')
DEBUG = False

# The secret key is used internally by Flask to encrypt session data stored
# in cookies. Make this unique for your app.
SECRET_KEY = 'imdf8a9f88q46fq8fds98dfgb7hshfdsaj9'

# This is used by micawber, which will attempt to generate rich media
# embedded objects with maxwidth=800.
SITE_WIDTH = 1200


app = Flask(__name__)
app.config.from_object(__name__)

# flask_db = FlaskDB(app)
# database = flask_db.database

##TEMPLATE FILTERS
def to_pretty_json(value):
    return json.dumps(value, sort_keys=True,
                      indent=4, separators=(',', ': '))


app.jinja_env.filters['tojson_pretty'] = to_pretty_json


def clean_sample_url(value):
    return value.replace('http', 'hxxp')


app.jinja_env.filters['clean_sample_url'] = clean_sample_url
### END TEMPLATE FILTERS

##TOPS
def get_top_ip_attackers():
    # ips = (IP
    #        .select(IP.address, fn.COUNT(IP.address).alias('ct'))
    #        .group_by(IP.address)
    #        .order_by(SQL('ct').desc())
    #        .limit(10))
    ips_ct = (Connection
           .select(Connection.ip_id, fn.COUNT(Connection.ip_id).alias('ct'))
           .group_by(Connection.ip_id)
           .order_by(SQL('ct').desc())
           .limit(10))
    return ips_ct


def get_countries():
    ips_countries = (IP
                     .select(IP.country, IP.iso_code, fn.COUNT(IP.country).alias('ct'))
                     .where(IP.country != None)
                     .group_by(IP.country)
                     .order_by(SQL('ct').desc()))
#                     .limit(10))
    return ips_countries


def get_samples():
    top_samples = (Sample
               .select(Sample.name, Sample.sha256sum, fn.COUNT(Sample.name).alias('ct'))
               .where(Sample.scan_result != None)
               .group_by(Sample.name)
               .order_by(SQL('ct').desc())
               .limit(10))
    return top_samples


def get_top_usernames():
    top_usernames = (Connection
                     .select(Connection.username, fn.COUNT(Connection.username).alias('ct'))
                     .group_by(Connection.username)
                     .order_by(SQL('ct').desc())
                     .limit(10))
    return top_usernames


def get_top_passwords():
    top_passwords = (Connection
                     .select(Connection.password, fn.COUNT(Connection.password).alias('ct'))
                     .group_by(Connection.password)
                     .order_by(SQL('ct').desc())
                     .limit(10))
    return top_passwords


def get_top_clients():
    top_clients = (Connection
                     .select(Connection.remote_version, fn.COUNT(Connection.remote_version).alias('ct'))
                     .group_by(Connection.remote_version)
                     .order_by(SQL('ct').desc())
                     .limit(10))
    return top_clients


def get_latest_conn_commands():
    commands = (Connection
                .select(Connection.username, Connection.password, Connection.command)
                .where(Connection.command != '')
                .order_by(Connection.id.desc())
                .limit(5))
    return commands


def get_latest_conn_countries():
    countries = (IP
                 .select(IP.address, IP.iso_code, IP.country, IP.asn_number, IP.asn_organization, IP.blacklist_count, IP.threat_level)
                 .join(Connection, JOIN.LEFT_OUTER)
                 .order_by(Connection.id.desc())
                 .limit(10)
    )
    return countries


def get_latest_conn_samples():
    latest_samples = (Sample
               .select(Sample.name, Sample.url, Sample.sha256sum)
               .order_by(Sample.id.desc())
               .limit(10))
    return latest_samples


@app.route('/connections')
def connections():
    password_count = Connection.select(Connection.password).distinct().count()
    username_count = Connection.select(Connection.username).distinct().count()
    client_count = Connection.select(Connection.remote_version).distinct().count()
    top_usernames = get_top_usernames()
    top_passwords = get_top_passwords()
    top_clients   = get_top_clients()

    data = {
        'password_count': password_count,
        'username_count': username_count,
        'client_count': client_count,
        'top_usernames': top_usernames,
        'top_passwords': top_passwords,
        'top_clients': top_clients,
    }
    return render_template('connections.html', data=data)


@app.route('/ips')
def ips():
    ips_top = get_top_ip_attackers()
    ips_countries = get_countries()
    ips_top_countries = ips_countries.limit(10)
    data        = {'ips': ips_top,
                   'ips_countries': ips_countries,
                   'ips_top_countries': ips_top_countries}
    return render_template('ips.html', data=data)


@app.route('/ips/<address>/')
def ip_detail(address):
    try:
        ip = IP.get(IP.address == address)
        return render_template('ip_detail.html', ip=ip)
    except:
        return ips()


@app.route('/samples')
def samples():
    samples_count = get_samples()
    data = {'top_samples': samples_count}
    return render_template('samples.html', data=data)


@app.route('/samples/<sha256>/')
def sample_detail(sha256):
    try:
        sample = Sample.get(Sample.sha256sum == sha256)
        return render_template('sample_detail.html', sample=sample)
    except:
        return samples()


@app.route('/')
def index():
#    ips                 = get_top_ip_attackers()
#    ips_countries       = get_countries()
#    ips_top_countries   = ips_countries.limit(10)
    ip_count            = IP.select().count()
    sample_count        = Sample.select().count()
    up_count            = (Connection
                            .select(Connection.username, Connection.password)
                            .group_by(Connection.username, Connection.password).count())
    latest_commands     = get_latest_conn_commands()
    latest_countries    = get_latest_conn_countries()
    latest_samples      = get_latest_conn_samples()
    data                = {
            'ip_count' : ip_count,
            'sample_count': sample_count,
            'up_count': up_count,
            'latest_countries': latest_countries,
            'latest_commands': latest_commands,
            'latest_samples': latest_samples,
    }
    return render_template('index.html', data=data)


def main():
    app.run(port=int(12322), host='0.0.0.0', debug=True)


if __name__ == '__main__':
    main()
