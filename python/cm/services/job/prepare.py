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

from core.job.dto import TaskPayloadDTO
from core.job.task import compose_task
from core.job.types import Task
from core.types import ActionID, ActionTargetDescriptor, CoreObjectDescriptor

from cm.services.job.run.repo import ActionRepoImpl, JobRepoImpl
from cm.services.job.types import TaskMappingDelta


def prepare_task_for_action(
    target: ActionTargetDescriptor,
    owner: CoreObjectDescriptor,
    action: ActionID,
    payload: TaskPayloadDTO,
    delta: TaskMappingDelta | None = None,
) -> Task:
    return compose_task(
        target=target,
        owner=owner,
        action=action,
        payload=payload,
        job_repo=JobRepoImpl,
        action_repo=ActionRepoImpl,
        delta=delta,
    )
