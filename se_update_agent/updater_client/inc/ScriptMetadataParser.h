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

#ifndef __METADATA_PARSER__
#define __METADATA_PARSER__
#include <SEUpdaterClient.h>
#include <iomanip>
#include <string>
#include <vector>

enum SemsScriptType { UPDATE_SCRIPT, LOAD_SCRIPT, GET_STATUS_SCRIPT };
enum PlatformID { SN220_V3, SN220_V5, SN300, SN330, SN470, INVALID };
enum ExecutionState { GET_STATUS, LOAD, UPDATE };
enum GetStatusResponseType { INSTANCE_DATA, MATCHING_ELF_DATA };

struct MatchingELF {
  std::vector<uint8_t> elf_aid_complete;
  std::vector<std::vector<uint8_t>> module_aids;
  std::vector<uint8_t> elf_version;
};

// Store response for Getstatus cmd
// 1. complete instance aid + associated elf aid
// 2. all matching elf aids + their version
// associated elf aid is searched in all matching elf aids
// to find current version installed on eSE
struct GetStatusResponse {
  std::vector<uint8_t> applet_aid_partial;
  std::vector<uint8_t> instance_aid_complete;
  std::vector<uint8_t> associated_elf_aid;
  std::vector<MatchingELF> matching_elfs;
  bool instance_data_recvd;
  bool matching_elf_data_recvd;
};
struct GetStatusScriptMetaInfo {
  SemsScriptType script_type;
  std::vector<std::vector<uint8_t>> applet_aids_partial;
  std::vector<uint8_t> signature;
  std::string script_path;
};

struct LoadUpdateScriptMetaInfo {
  SemsScriptType script_type;
  std::vector<uint8_t> applet_aid_partial;
  std::vector<uint8_t> elf_aid_complete;
  std::vector<uint8_t> elf_version;
  std::vector<std::pair<std::vector<uint8_t>, std::streampos>>
      signatures;  // multiple SEMS scripts embedded within one file

  std::string script_path;
  uint8_t platform_id;
};

struct SemsScriptInfo {
  std::vector<uint8_t> applet_aid_partial;
  bool load_script_exists;
  bool update_script_exists;
  bool pre_load_required;
  bool update_required;
  struct LoadUpdateScriptMetaInfo update_script;
  struct LoadUpdateScriptMetaInfo load_script;
};

/**
 * local method to parse sems metadata per script
 */
int ParseSemsMetadata(const char* path);

/**
 * Prints parsed info for all scripts
 */
void DisplayAllScriptsInfo();

/**
 * Returns parsed sems metadata for GETSTATUS script
 */
const struct GetStatusScriptMetaInfo GetStatusScriptData();

/**
 * Returns parsed sems metadata for all LOAD/UPDATE type scripts
 */
const std::vector<struct SemsScriptInfo> GetEnumeratedScriptsData();

/**
 * Parses metadata field for all scripts available under
 * dir script_dir_path
 */
SESTATUS ParseSemsScriptsMetadata(std::string script_dir_path);

/**
 * Parses response received during GETSTATUS script execution
 * ignores otherwise
 */
bool ParseResponse(uint8_t* recvBuffer, int32_t recvBuffersize);

/**
 * Iterates over recevied GETSTATUS response and LOAD/UPDATE scripts
 * enumerated metadata info to determine LOAD or UPDATE type script
 * execution
 */
void CheckLoad_Or_UpdateRequired(bool* load_req, bool* update_req);

/**
 * Sets current execution state
 */
void SetScriptExecutionState(ExecutionState script_exe_state);

/**
 * Utility function to print vector contents
 */
std::string toString(const std::vector<uint8_t>& vec);

#endif
