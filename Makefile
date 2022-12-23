BRANCH_NAME ?= $(shell git rev-parse --abbrev-ref HEAD)
APP_IMAGE ?= hub.adsw.io/adcm/adcm
APP_TAG ?= $(subst /,_,$(BRANCH_NAME))
SELENOID_HOST ?= 10.92.2.65
SELENOID_PORT ?= 4444

.PHONY: help

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

describe:
	@echo '{"version": "$(shell date '+%Y.%m.%d.%H')","commit_id": "$(shell git log --pretty=format:'%h' -n 1)"}' > config.json
	cp config.json web/src/assets/config.json

buildss:
	podman run -i --rm -v $(CURDIR)/go:/code -w /code docker.io/golang sh -c "make"

buildjs:
	podman run -i --rm -v $(CURDIR)/wwwroot:/wwwroot -v $(CURDIR)/web:/code -w /code  docker.io/node:16-alpine ./build.sh

build_base:
	podman build . -t $(APP_IMAGE):$(APP_TAG)

build: describe buildss buildjs build_base

unittests: buildss buildjs build_base
	mkdir -p /tmp/adcm_db
	podman run -d -p 5432:5432 -v ./init-user-db.sh:/docker-entrypoint-initdb.d/init-user-db.sh \
	-v /tmp/adcm_db:/var/lib/postgresql/data -e POSTGRES_PASSWORD="test_password" \
	-e POSTGRES_ADCM_PASS="test_password" --name db docker.io/postgres
	podman run --rm -e DJANGO_SETTINGS_MODULE=adcm.settings -v ./data:/adcm/data \
	$(APP_IMAGE):$(APP_TAG) sh -c "pip install --no-cache -r /adcm/requirements.txt && /adcm/python/manage.py test /adcm/python -v 2"
	podman stop db
	podman rm db

pytest:
	podman pull hub.adsw.io/library/functest:3.10.6.slim.buster-x64
	podman run -i --rm --shm-size=4g -v /var/run/docker.sock:/var/run/docker.sock --network=host \
	-v $(CURDIR)/:/adcm -w /adcm/ \
	-e BUILD_TAG=${BUILD_TAG} -e ADCMPATH=/adcm/ -e PYTHONPATH=${PYTHONPATH}:python/ \
	-e SELENOID_HOST="${SELENOID_HOST}" -e SELENOID_PORT="${SELENOID_PORT}" -e ALLURE_TESTPLAN_PATH="${ALLURE_TESTPLAN_PATH}" \
	hub.adsw.io/library/functest:3.10.6.slim.buster-x64 /bin/sh -e \
	./pytest.sh ${PYTEST_MARK_KEY} ${PYTEST_MARK_VALUE} ${PYTEST_EXPRESSION_KEY} ${PYTEST_EXPRESSION_VALUE} \
	--adcm-image="hub.adsw.io/adcm/adcm:$(subst /,_,$(BRANCH_NAME))" \

pytest_release:
	podman pull hub.adsw.io/library/functest:3.10.6.slim.buster.firefox-x64
	podman run -i --rm --shm-size=4g -v /var/run/docker.sock:/var/run/docker.sock --network=host \
	-v $(CURDIR)/:/adcm -v ${LDAP_CONF_FILE}:${LDAP_CONF_FILE} -w /adcm/ \
	-e BUILD_TAG=${BUILD_TAG} -e ADCMPATH=/adcm/ -e PYTHONPATH=${PYTHONPATH}:python/ \
	-e SELENOID_HOST="${SELENOID_HOST}" -e SELENOID_PORT="${SELENOID_PORT}" -e ALLURE_TESTPLAN_PATH="${ALLURE_TESTPLAN_PATH}" \
	hub.adsw.io/library/functest:3.10.6.slim.buster.firefox-x64 /bin/sh -e \
	./pytest.sh --adcm-image="hub.adsw.io/adcm/adcm:$(subst /,_,$(BRANCH_NAME))" --ldap-conf ${LDAP_CONF_FILE} \
	${PYTEST_MARK_KEY} ${PYTEST_MARK_VALUE} ${PYTEST_EXPRESSION_KEY} ${PYTEST_EXPRESSION_VALUE}


ng_tests:
	podman pull hub.adsw.io/library/functest:3.8.6.slim.buster_node16-x64
	podman run -i --rm -v $(CURDIR)/:/adcm -w /adcm/web hub.adsw.io/library/functest:3.8.6.slim.buster_node16-x64 ./ng_test.sh

npm_check:
	podman run -i --rm -v $(CURDIR)/wwwroot:/wwwroot -v $(CURDIR)/web:/code -w /code  node:16-alpine ./npm_check.sh

pretty:
	black license_checker.py python tests
	autoflake -r -i --remove-all-unused-imports --exclude apps.py,python/ansible/plugins,python/init_db.py,python/task_runner.py,python/backupdb.py,python/job_runner.py,python/drf_docs.py license_checker.py python tests
	isort license_checker.py python tests
	python license_checker.py --fix --folders python go
