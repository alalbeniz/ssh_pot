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


def to_pretty_json(value):
    return json.dumps(value, sort_keys=True,
                      indent=4, separators=(',', ': '))


app.jinja_env.filters['tojson_pretty'] = to_pretty_json


def clean_sample_url(value):
    return value.replace('http', 'hxxp')


app.jinja_env.filters['clean_sample_url'] = clean_sample_url


def get_top_ip_attackers():
    ips = (IP
           .select(IP.address, fn.COUNT(IP.address).alias('ct'))
           .group_by(IP.address)
           .order_by(SQL('ct').desc())
           .limit(10))
    return ips


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
    return render_template('connections.html')


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

    latest_commands     = get_latest_conn_commands()
    latest_countries    = get_latest_conn_countries()
    latest_samples      = get_latest_conn_samples()
    data                = {
            #'ips' : ips,
            'latest_countries': latest_countries,
            'latest_commands': latest_commands,
            'latest_samples': latest_samples,
    }
    return render_template('index.html', data=data)


def main():
    app.run(port=int(12322), host='0.0.0.0', debug=True)


if __name__ == '__main__':
    main()
