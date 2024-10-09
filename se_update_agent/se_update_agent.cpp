/******************************************************************************
 *
 *  Copyright 2025 NXP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
#include <SEUpdaterClient.h>
#include <ScriptMetadataParser.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <log/log.h>
#include <cstdlib>
#include <cstring>

#undef LOG_TAG
#define LOG_TAG "se_update_agent"

int main(int argc, char* argv[]) {
  LOG(INFO) << "se_update_agent starting up !!!";

  if (argc != 3) {
    LOG(ERROR) << "se_update_agent requires 2 arguments";
    LOG(ERROR) << "Usage: se_update_agent <option> <script-dir-path>";
    LOG(ERROR) << "option: check-update or apply-update or log-status";
    LOG(ERROR) << "se_update_agent exiting";
    exit(-1);
  }
  std::string script_dir_path = argv[2];

  if (!strcmp(argv[1], "check-update")) {
    LOG(INFO) << "perform action check-update";
    PrepareUpdate(script_dir_path);
  } else if (!strcmp(argv[1], "apply-update")) {
    LOG(INFO) << "perform action apply-update";
    PerformUpdate(script_dir_path);
  } else if (!strcmp(argv[1], "log-status")) {
  } else {
#ifdef NXP_BOOTTIME_UPDATE
    LOG(INFO) << "perform Legacy Boottime update";
    checkEseClientUpdate();
    perform_eSEClientUpdate();
#endif
  }
  LOG(INFO) << "se_update_agent exiting";
  return 0;
}
