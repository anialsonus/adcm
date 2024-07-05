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

from datetime import datetime
from typing import Callable
import os
import logging

from core.job.runners import (
    ADCMSettings,
    AnsibleSettings,
    ExternalSettings,
    IntegrationsSettings,
    JobProcessor,
    TaskRunner,
)
from core.job.types import ExecutionStatus
from django.conf import settings
from django.utils import timezone

from cm import status_api
from cm.services.job.run._target_factories import ExecutionTargetFactory
from cm.services.job.run.repo import JobRepoImpl
from cm.services.job.run.runners import JobSequenceRunner
from cm.services.status import notify

logger = logging.getLogger("task_runner_err")

_factory = ExecutionTargetFactory()


class SubprocessRunnerEnvironment:
    @property
    def pid(self) -> int:
        return os.getpid()

    def now(self) -> datetime:
        return timezone.now()


def get_default_runner() -> TaskRunner:
    return _get_runner()


def get_restart_runner() -> TaskRunner:
    return _get_runner(filter_predicate=lambda job: job.status != ExecutionStatus.SUCCESS)


def _get_runner(filter_predicate: Callable = id) -> TaskRunner:
    return JobSequenceRunner(
        job_processor=JobProcessor(convert=_factory, filter_predicate=filter_predicate),
        settings=_prepare_settings(),
        repo=JobRepoImpl,
        environment=SubprocessRunnerEnvironment(),
        notifier=status_api,
        status_server=notify,
        logger=logger,
    )


def _prepare_settings() -> ExternalSettings:
    return ExternalSettings(
        adcm=ADCMSettings(code_root_dir=settings.CODE_DIR, run_dir=settings.RUN_DIR, log_dir=settings.LOG_DIR),
        ansible=AnsibleSettings(ansible_secret_script=settings.CODE_DIR / "ansible_secret.py"),
        integrations=IntegrationsSettings(status_server_token=settings.STATUS_SECRET_KEY),
    )
