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
from abc import ABC
from datetime import datetime
from functools import partial
from typing import Callable, Generator, Iterable, NamedTuple
from unittest.mock import patch

from core.job.executors import ExecutionResult, Executor, ExecutorConfig
from core.job.runners import ExecutionTarget, ExecutionTargetFactoryI, ExternalSettings, TaskRunner
from core.job.types import Job, ScriptType, Task
from django.utils import timezone
from typing_extensions import Self

from cm.models import TaskLog
from cm.services.job.run import get_default_runner, run_task
from cm.services.job.run._target_factories import ExecutionTargetFactory


class FakePopen(NamedTuple):
    pid: int


class FailedJobInfo(NamedTuple):
    position: int
    return_code: int


# ExecutionTarget Factories


class ExecutionTargetFactoryDummyMock(ExecutionTargetFactory):
    def __init__(self, failed_job: FailedJobInfo | None = None):
        super().__init__()

        self._failed_job = failed_job

    def __call__(
        self, task: Task, jobs: Iterable[Job], configuration: ExternalSettings
    ) -> Generator[ExecutionTarget, None, None]:
        _ = task
        for job_num, job in enumerate(jobs):
            work_dir = configuration.adcm.run_dir / str(job.id)

            if job.type == ScriptType.INTERNAL:
                internal_script_func = self._supported_internal_scripts[job.script]
                script = partial(internal_script_func, task=task)
                executor = InternalExecutorMock(config=ExecutorConfig(work_dir=work_dir), script=script)

            else:
                executor_class = SuccessExecutorMock
                executor_kwargs = {}
                if self._failed_job is not None and job_num == self._failed_job.position:
                    executor_class = FailExecutorMock
                    executor_kwargs = {"return_code": self._failed_job.return_code}

                executor = executor_class(
                    script_type=job.script,
                    config=ExecutorConfig(work_dir=configuration.adcm.run_dir / str(job.id)),
                    **executor_kwargs,
                )

            yield ExecutionTarget(
                job=job,
                executor=executor,
                environment_builders=(),
                finalizers=(),
            )


# Executors


class MockExecutor(Executor, ABC):
    def execute(self) -> Self:
        return self

    def wait_finished(self) -> Self:
        self._result = ExecutionResult(code=0)
        return self


class InternalExecutorMock(MockExecutor):
    script_type = "internal"

    def __init__(self, config: ExecutorConfig, script: Callable[[], int]):
        super().__init__(config=config)
        self._script = script

    def execute(self) -> Self:
        return self._script()


class SuccessExecutorMock(MockExecutor):
    def __init__(self, script_type: str, **kwargs):
        super().__init__(**kwargs)
        self._script_type = script_type

    @property
    def script_type(self) -> str:
        return self._script_type


class FailExecutorMock(SuccessExecutorMock):
    def __init__(self, return_code: int, **kwargs):
        super().__init__(**kwargs)

        if return_code <= 0:
            raise ValueError("Only positive integers allowed")

        self._return_code = return_code

    def wait_finished(self) -> Self:
        self._result = ExecutionResult(code=self._return_code)
        return self


# Custom Mocks


class SubprocessRunnerMockEnvironment:
    @property
    def pid(self) -> int:
        return 5_000_000

    def now(self) -> datetime:
        return timezone.now()


_DEFAULT_ETF_MOCK = ExecutionTargetFactoryDummyMock()


class RunTaskMock:
    def __init__(self, execution_target_factory: ExecutionTargetFactoryI = _DEFAULT_ETF_MOCK):
        self.target_task: TaskLog | None = None
        self.runner: TaskRunner | None = None
        self._execution_target_factory = execution_target_factory
        self._run_patch = None

    def __call__(self, task: TaskLog) -> None:
        self.target_task = task
        with patch("cm.services.job.run._task.subprocess.Popen", return_value=FakePopen(pid=101)):
            run_task(task)

        with patch("cm.services.job.run._impl._factory", new=self._execution_target_factory), patch(
            "cm.services.job.run._impl.SubprocessRunnerEnvironment", new=SubprocessRunnerMockEnvironment
        ):
            self.runner = get_default_runner()

    def __enter__(self):
        self._run_patch = patch("cm.services.job.action.run_task", new=self)
        return self._run_patch.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return_ = None
        if self._run_patch:
            return_ = self._run_patch.__exit__(exc_type, exc_val, exc_tb)
            self._run_patch = None

        return return_
