// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

export interface InnerIssue {
  id: number;
  name: string;
  issue: Issue;
}

export interface Issue<K = 'host' | 'service' | 'cluster' | 'provider'> {
  [K: string]: false | InnerIssue;
  K: InnerIssue;
}

/**
 * Check Issue
 * @returns true if there's not issues
 * @param issue 
 */
export const notIssue = (issue: Issue): boolean => !(issue && Object.keys(issue).length);
