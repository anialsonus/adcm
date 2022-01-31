#!/bin/sh
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

name=adcm_test
port=8000

module=adcm.wsgi:application

socket=/tmp/"${name}".sock
pidfile=/tmp/"${name}".pid
logfile=/tmp/"${name}".error.log

if [ "${2}" ]; then
    port="${2}"
fi

if [ -d /adcm/venv/default ]; then
    venv="--venv /adcm/venv/default/"
else
    venv=""
fi

case "${1}" in
    "start")
        # shellcheck disable=SC2086
        uwsgi --module="${module}" --socket "${socket}" --master --pidfile="${pidfile}" \
            --harakiri=30 --max-requests=5000 --processes=2 --vacuum \
            --http :"${port}" --daemonize="${logfile}" ${venv}
        ;;
    "stop")
        uwsgi --stop "${pidfile}"
        ;;
    *)
        echo "Usage: server.sh {start|stop}"
        ;;
esac
