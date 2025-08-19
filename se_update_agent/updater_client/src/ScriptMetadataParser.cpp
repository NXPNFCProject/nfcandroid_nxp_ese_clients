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

#include "ScriptMetadataParser.h"
#include <Utils.h>

#include <android-base/logging.h>
#include <dirent.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

const std::vector<std::string> MANDATORY_METADATA_FIELDS_LOAD_UPDATE_SCRIPT = {
    "SEMSType", "AppletAID", "ELFAID", "ELFVersion", "PlatformID"};
const std::vector<std::string> MANDATORY_METADATA_FIELDS_GETSTATUS_SCRIPT = {
    "SEMSType", "AppletAID1"};

#define FIRST_COL_WIDTH 40
#define OTHER_COL_WIDTH 20

void PrintAllParsedMetadata();
static std::vector<struct LoadUpdateScriptMetaInfo> load_update_script;
static std::vector<struct SemsScriptInfo> all_scripts_info;
struct GetStatusScriptMetaInfo getstatus_script;
static std::vector<struct GetStatusResponse> getstatus_response;

static ExecutionState exe_state;

std::vector<std::string> rows;

const std::vector<struct SemsScriptInfo> GetEnumeratedScriptsData() {
  return all_scripts_info;
}

const struct GetStatusScriptMetaInfo GetStatusScriptData() {
  return getstatus_script;
}
void ResetGlobalMetadataState(bool clear_version_table) {
  load_update_script.clear();
  all_scripts_info.clear();
  getstatus_response.clear();
  memset(&getstatus_script, 0, sizeof(GetStatusScriptMetaInfo));
  exe_state = ExecutionState::GET_STATUS;
  if (clear_version_table) {
    rows.clear();
  }
}

static uint8_t Numof_lengthbytes(uint8_t* read_buf, int32_t* pLen) {
  static const char fn[] = "Numof_lengthbytes";
  uint8_t len_byte = 0, i = 0;
  int32_t wLen = 0;
  LOG(DEBUG) << fn << ":enter";

  if (read_buf[i] == 0x00) {
    LOG(DEBUG) << "Invalid length zero";
    len_byte = 0x00;
  } else if ((read_buf[i] & 0x80) == 0x80) {
    len_byte = read_buf[i] & 0x0F;
    len_byte = len_byte + 1;  // 1 byte added for byte 0x81
  } else {
    len_byte = 0x01;
  }
  /*
   * To get the length of the value field
   * */
  switch (len_byte) {
    case 0:
      wLen = read_buf[0];
      break;
    case 1:
      /*1st byte is the length*/
      wLen = read_buf[0];
      break;
    case 2:
      /*2nd byte is the length*/
      wLen = read_buf[1];
      break;
    case 3:
      /*1st and 2nd bytes are length*/
      wLen = read_buf[1];
      wLen = ((wLen << 8) | (read_buf[2]));
      break;
    case 4:
      /*3bytes are the length*/
      wLen = read_buf[1];
      wLen = ((wLen << 16) | (read_buf[2] << 8));
      wLen = (wLen | (read_buf[3]));
      break;
    default:
      LOG(ERROR) << "default case";
      break;
  }

  *pLen = wLen;
  LOG(DEBUG) << fn << ": exit; len_bytes=" << len_byte << " Length=" << *pLen;
  return len_byte;
}

inline int SSCANF_BYTE(const char* buf, const char* format, void* pVal) {
  int Result = 0;

  if ((NULL != buf) && (NULL != format) && (NULL != pVal)) {
    unsigned int dwVal;
    unsigned char* pTmp = (unsigned char*)pVal;
    Result = sscanf(buf, format, &dwVal);

    (*pTmp) = (unsigned char)(dwVal & 0x000000FF);
  }
  return Result;
}

// Function to sort vector of LoadUpdateScriptMetaInfo by elf_version
// (descending) and elf_base_version (descending)
void sortScriptsByVersion(std::vector<LoadUpdateScriptMetaInfo>& scripts) {
  std::sort(
      scripts.begin(), scripts.end(),
      [](const LoadUpdateScriptMetaInfo& a, const LoadUpdateScriptMetaInfo& b) {
        // Compare elf_version first (higher version comes first)
        if (a.elf_version != b.elf_version) {
          return a.elf_version > b.elf_version;
        }
        // If elf_version is equal, compare elf_base_version (descending)
        return a.elf_base_version > b.elf_base_version;
      });
}

// Helper function to compare two version vectors (e.g., ELFVersion)
bool isVersionGreater(const std::vector<uint8_t>& v1,
                      const std::vector<uint8_t>& v2) {
  if (v1.size() != v2.size()) return v1.size() > v2.size();
  return v1 > v2;
}

// Function to filter scripts based on conditions
std::vector<LoadUpdateScriptMetaInfo> filterScripts(
    const std::vector<LoadUpdateScriptMetaInfo>& scripts,
    SemsScriptType script_type, const std::vector<uint8_t>& applet_aid) {
  std::vector<LoadUpdateScriptMetaInfo> filtered_scripts;
  // Filter scripts by script_type and AppletAID
  std::vector<LoadUpdateScriptMetaInfo> matching_scripts;
  for (const auto& script : scripts) {
    if (script.script_type == script_type &&
        script.applet_aid_partial == applet_aid) {
      matching_scripts.push_back(script);
    }
  }

  if (matching_scripts.empty()) {
    LOG(WARNING) << "No script with script_type:" << script_type
                 << " found for applet_aid: " << toString(applet_aid);
    return {};
  }

  // Count scripts with ELFBaseVersion and without ELFBaseVersion
  std::vector<LoadUpdateScriptMetaInfo> scripts_with_base;
  std::vector<LoadUpdateScriptMetaInfo> scripts_without_base;
  for (const auto& script : matching_scripts) {
    if (script.elf_base_version.empty()) {
      scripts_without_base.push_back(script);
    } else {
      scripts_with_base.push_back(script);
    }
  }

  // Case: Single script with no ELFBaseVersion, select it
  if (scripts_with_base.empty() && scripts_without_base.size() == 1) {
    filtered_scripts.push_back(scripts_without_base[0]);
    return filtered_scripts;
  }

  // Case: Multiple scripts with no ELFBaseVersion, reject
  if (scripts_with_base.empty() && scripts_without_base.size() > 1) {
    LOG(ERROR) << "Multiple scripts with no ELFBaseVersion detected for AID: "
               << toString(applet_aid);
    throw std::runtime_error("Duplicate script files with no ELFBaseVersion");
  }

  // Case: Handle scripts with matching ELFBaseVersion
  if (!scripts_with_base.empty()) {
    // Group scripts by ELFBaseVersion
    std::unordered_map<std::string, std::vector<LoadUpdateScriptMetaInfo>>
        base_version_groups;
    for (const auto& script : scripts_with_base) {
      std::string base_version_str(script.elf_base_version.begin(),
                                   script.elf_base_version.end());
      base_version_groups[base_version_str].push_back(script);
    }

    // Process each ELFBaseVersion group
    for (const auto& base_group : base_version_groups) {
      // Check for duplicate ELFVersion within this ELFBaseVersion group
      std::unordered_map<std::string, std::vector<LoadUpdateScriptMetaInfo>>
          version_groups;
      for (const auto& script : base_group.second) {
        std::string version_str(script.elf_version.begin(),
                                script.elf_version.end());
        version_groups[version_str].push_back(script);
      }

      // Case: Check for duplicate scripts with same ELFBaseVersion and
      // ELFVersion
      for (const auto& version_group : version_groups) {
        if (version_group.second.size() > 1) {
          std::string base_version_str =
              toString(version_group.second[0].elf_base_version);
          std::string version_str =
              toString(version_group.second[0].elf_version);
          LOG(ERROR) << "Duplicate scripts with ELFBaseVersion "
                     << base_version_str << " and ELFVersion= " << version_str
                     << " for AID: " << toString(applet_aid);
          throw std::runtime_error(
              "Duplicate script files with same ELFBaseVersion and ELFVersion");
        }
      }
      // Case: Select script with the highest ELFVersion
      const LoadUpdateScriptMetaInfo* latest_script = nullptr;
      for (const auto& version_group : version_groups) {
        const auto& script = version_group.second[0];
        if (!latest_script ||
            isVersionGreater(script.elf_version, latest_script->elf_version)) {
          latest_script = &script;
        }
      }
      filtered_scripts.push_back(*latest_script);
    }
  }

  return filtered_scripts;
}

// Filters both LOAD(if available) and UPDATE type of
// scripts for each applet. Checks for their compatibility
// and prepares SemsScriptInfo for given applet aid.
std::vector<SemsScriptInfo> filterScriptsForAid(
    const std::vector<LoadUpdateScriptMetaInfo>& scripts,
    const std::vector<uint8_t>& applet_aid) {
  std::vector<LoadUpdateScriptMetaInfo> selected_update_scripts,
      selected_load_scripts;
  std::vector<SemsScriptInfo> filtered_scripts;

  try {
    selected_update_scripts = filterScripts(scripts, UPDATE_SCRIPT, applet_aid);
    for (auto& item : selected_update_scripts) {
      LOG(DEBUG) << item.script_path << " " << toString(item.elf_version) << " "
                 << toString(item.elf_base_version) << std::endl;
    }
  } catch (const std::exception& e) {
    LOG(ERROR) << "Exception while filtering for UPDATE_SCRIPT: " << e.what();
    // Reaching here means there is no valid update/load scripts for this
    // applet_aid
    return {};
  }

  try {
    selected_load_scripts = filterScripts(scripts, LOAD_SCRIPT, applet_aid);
    for (auto& item : selected_load_scripts) {
      LOG(DEBUG) << item.script_path << " " << toString(item.elf_version) << " "
                 << toString(item.elf_base_version);
    }
  } catch (const std::exception& e) {
    LOG(ERROR) << "Exception while filtering for LOAD_SCRIPT: " << e.what();
    // Reaching here means provided load scripts for this applet_aid are not
    // valid
    return {};
  }

  // For AMD-H based upgrade: Both load and update type scripts are required
  bool amdH_upgrade_compatible = false;

  // For Non AMD-H based upgrade: only update type scripts are required
  bool non_amdH_upgrade_only = false;

  if (selected_load_scripts.size() > 0) {
    sortScriptsByVersion(selected_load_scripts);
    sortScriptsByVersion(selected_update_scripts);

    // load and update scripts metadata(except script_type field) should match
    amdH_upgrade_compatible = true;

    if (selected_update_scripts.size() != selected_load_scripts.size()) {
      LOG(ERROR) << "Error: load and update scripts size doesnot match";
      amdH_upgrade_compatible = false;
    } else {
      for (int i = 0; i < selected_update_scripts.size(); i++) {
        if ((selected_update_scripts[i].elf_version !=
             selected_load_scripts[i].elf_version) ||
            selected_update_scripts[i].elf_base_version !=
                selected_load_scripts[i].elf_base_version) {
          LOG(ERROR) << "Error: load and update script values don't match";
          amdH_upgrade_compatible = false;
          break;
        }
      }
    }
  } else {
    // No Load script for this AppletAID.
    // Consider this Non-AMDH based upgrade
    non_amdH_upgrade_only = true;
  }

  if ((non_amdH_upgrade_only || amdH_upgrade_compatible)) {
    struct LoadUpdateScriptMetaInfo empty = {};
    empty.script_type = INVALID_SCRIPT;
    for (int i = 0; i < selected_update_scripts.size(); i++) {
      struct SemsScriptInfo entry = {};
      entry.applet_aid_partial = selected_update_scripts[i].applet_aid_partial;
      entry.load_script_exists =
          (!non_amdH_upgrade_only && amdH_upgrade_compatible);
      entry.update_script_exists =
          (non_amdH_upgrade_only || amdH_upgrade_compatible);
      entry.update_script = (non_amdH_upgrade_only || amdH_upgrade_compatible)
                                ? selected_update_scripts[i]
                                : empty;
      entry.load_script = (!non_amdH_upgrade_only && amdH_upgrade_compatible)
                              ? selected_load_scripts[i]
                              : empty;
      filtered_scripts.push_back(entry);
    }
  }

  return filtered_scripts;
}

// Function to trim leading and trailing whitespace
std::string trim(const std::string& str) {
  size_t first = str.find_first_not_of(' ');
  if (first == std::string::npos) return "";
  size_t last = str.find_last_not_of(' ');
  return str.substr(first, last - first + 1);
}

// Parses metadata fields for all scripts available under given path
ParseMetadataError ParseSemsScriptsMetadata(std::string script_dir_path,
                                            bool clear_version_table) {
  std::string path = std::move(script_dir_path);

  DIR* dir = opendir(path.c_str());
  if (dir == nullptr) {
    LOG(ERROR) << "Error opening directory: " << path;
    return ParseMetadataError::FILE_NOT_FOUND;
  }

  ResetGlobalMetadataState(clear_version_table);

  struct dirent* entry;
  bool parse_success = true;
  struct stat sb;

  while ((entry = readdir(dir)) != nullptr) {
    std::string name = entry->d_name;
    if (name == "." || name == "..") continue;
    std::string fullPath = path + "/" + name;
    if (stat(fullPath.c_str(), &sb) == 0 && !(sb.st_mode & S_IFDIR)) {
      ParseMetadataError result = ParseSemsMetadata(fullPath.c_str());
      if (result != ParseMetadataError::SUCCESS) {
        LOG(ERROR) << "Error" << result << " parsing: " << path;
        closedir(dir);
        return result;
      }
    }
  }
  if (dir != NULL) {
    closedir(dir);
  }
  if (getstatus_script.script_path.empty()) {
    LOG(ERROR) << "GETSTATUS SCRIPT not found under " << path;
    return ParseMetadataError::FILE_NOT_FOUND;
  }
  return ParseMetadataError::SUCCESS;
}

// Filters all script based on
// 1. chip type
// 2. compatible/valid script based on target and base version for each applet
ParseMetadataError FilterScripts(std::vector<uint8_t>& chip_type) {
  // find corresponding platformID
  PlatformID p_id = PlatformID::INVALID;
  for (const auto& item : ChipIds) {
    if (item.first == chip_type) {
      p_id = item.second;
      break;
    }
  }

  if (p_id == PlatformID::SN220_V5 &&
      getSEOsVersion() == SN220_V3_JCOP_BASE_REV_NUM) {
    // SN220_V3 vendor ID was updated to 0x0000000021 with JCOP Update REV num
    // 0x03D043
    p_id = PlatformID::SN220_V3;
  }

  std::vector<struct LoadUpdateScriptMetaInfo> scripts_filtered_for_chiptype;

  for (const auto& script : load_update_script) {
    bool script_invalid = false;
    switch (p_id) {
      case PlatformID::SN220_V3: {
        if (script.script_type == SemsScriptType::LOAD_SCRIPT) {
          // AMD-H based Update is not supported for SN220_V3
          LOG(WARNING)
              << "LOAD_SCRIPT Type is not supported for chiptype:SN220_V3";
          script_invalid = true;
          return ParseMetadataError::INVALID_SEMS_TYPE;
        } else {
          script_invalid |= script.script_type == SemsScriptType::UPDATE_SCRIPT
                                ? (script.platform_id != PlatformID::SN220_V3)
                                : 0;
        }
      } break;
      case PlatformID::SN220_V5:
        script_invalid = script.script_type == SemsScriptType::LOAD_SCRIPT
                             ? (script.platform_id != PlatformID::SN220_V5)
                             : 0;
        script_invalid |= script.script_type == SemsScriptType::UPDATE_SCRIPT
                              ? (script.platform_id != PlatformID::SN220_V5)
                              : 0;
        if (script_invalid) {
          LOG(INFO) << "Script is invalid for chiptype:SN220_V5";
        }
        break;
      case PlatformID::SN300:
      case PlatformID::SN330:
        script_invalid = script.script_type == SemsScriptType::LOAD_SCRIPT
                             ? (script.platform_id != PlatformID::SN300 &&
                                script.platform_id != PlatformID::SN330)
                             : 0;
        script_invalid |= script.script_type == SemsScriptType::UPDATE_SCRIPT
                              ? (script.platform_id != PlatformID::SN300 &&
                                 script.platform_id != PlatformID::SN330)
                              : 0;
        if (script_invalid) {
          LOG(INFO) << "Script is invalid for chiptype:SN300/SN330";
        }
        break;
      default:
        script_invalid = true;
        break;
    }
    if (!script_invalid) {
      scripts_filtered_for_chiptype.push_back(script);
    }
  }

  // Remove invalid scripts for each Applet AID
  std::vector<struct SemsScriptInfo> valid_scripts;
  auto getstatus_script_data = GetStatusScriptData();
  for (const auto& applet_aid : getstatus_script_data.applet_aids_partial) {
    auto filtered_scripts_for_aid =
        filterScriptsForAid(scripts_filtered_for_chiptype, applet_aid);
    valid_scripts.insert(valid_scripts.end(), filtered_scripts_for_aid.begin(),
                         filtered_scripts_for_aid.end());
  }
  all_scripts_info = valid_scripts;
  return ParseMetadataError::SUCCESS;
}

// Print enumerated data for each SEMS script
void DisplayAllScriptsInfo() {
  LOG(INFO) << "Printing All scripts info";
  for (int i = 0; i < all_scripts_info.size(); i++) {
    LOG(INFO) << i << "." << "Parital AID:"
              << toString(all_scripts_info[i].applet_aid_partial);
    LOG(INFO) << "  preload_required : "
              << all_scripts_info[i].pre_load_required;
    LOG(INFO) << "  update_required : " << all_scripts_info[i].update_required;

    if (all_scripts_info[i].load_script_exists)
      LOG(INFO) << "  LOAD script path: "
                << all_scripts_info[i].load_script.script_path;
    else
      LOG(INFO) << "  LOAD script does not exist";
    if (all_scripts_info[i].update_script_exists)
      LOG(INFO) << "  UPDATE script path: "
                << all_scripts_info[i].update_script.script_path;
    else
      LOG(INFO) << "  UPDATE script does not exist";
  }
}

// Print version info from eSE and Update package for each applet
void PrintVersionTable() {
  std::ostringstream table;

  // Header
  table << "| " << std::left << std::setw(FIRST_COL_WIDTH) << "AppletAID"
        << "| " << std::setw(OTHER_COL_WIDTH) << "Update Pkg Version"
        << "| " << std::setw(OTHER_COL_WIDTH) << "Installed Version"
        << "|\n";

  // Separator
  table << "|" << std::string(FIRST_COL_WIDTH, '-') << "-"
        << "|" << std::string(OTHER_COL_WIDTH, '-') << "-"
        << "|" << std::string(OTHER_COL_WIDTH, '-') << "-|\n";

  // Combine header and rows
  for (const auto& row : rows) {
    table << row << "\n";
  }
  LOG(INFO) << "\n" << table.str();
}

// Function to determine which script needs to be executed for Applet update

// Iterates over each SemsScriptInfo, compares its target and base version info
// with GetStatus script response to determine if script execution is needed.

void CheckLoad_Or_UpdateRequired(bool* load_req, bool* update_req) {
  for (int i = 0; i < all_scripts_info.size(); i++) {
    auto load_script_elf_aid = all_scripts_info[i].load_script.elf_aid_complete;
    auto load_script_elf_ver = all_scripts_info[i].load_script.elf_version;
    auto update_script_elf_ver = all_scripts_info[i].update_script.elf_version;
    auto update_script_elf_base_ver =
        all_scripts_info[i].update_script.elf_base_version;

    bool load_required = false;
    bool update_required = false;
    bool applet_exists = false;

    int k = 0;
    for (; k < getstatus_response.size(); k++) {
      if (all_scripts_info[i].applet_aid_partial ==
          getstatus_response[k].applet_aid_partial) {
        if (getstatus_response[k].instance_data_recvd) applet_exists = true;

        break;
      }
    }

    std::vector<uint8_t> installed_elf_version;
    // check if UPDATE script is required
    // Assuming existing installed_elf_aid is different
    // from the ELF AID we are updating to
    if (applet_exists) {
      auto installed_elf_aid = getstatus_response[k].associated_elf_aid;
      for (auto matching_elf : getstatus_response[k].matching_elfs) {
        if (installed_elf_aid == matching_elf.elf_aid_complete) {
          LOG(INFO) << "Installed elf aid" << toString(installed_elf_aid);
          LOG(INFO) << "script_elf_ver:" << toString(update_script_elf_ver);
          LOG(INFO) << "script_elf_base_ver:"
                    << toString(update_script_elf_base_ver);
          LOG(INFO) << "Installed_elf_ver:"
                    << toString(matching_elf.elf_version);
          installed_elf_version = matching_elf.elf_version;

          if (isVersionGreater(update_script_elf_ver, installed_elf_version)) {
            if (update_script_elf_base_ver.empty() ||
                update_script_elf_base_ver ==
                    std::vector<uint8_t>{0x00, 0x00}) {
              // Scripts without ELFBaseVersion metadata field
              update_required = true;
            } else if (update_script_elf_base_ver == installed_elf_version) {
              update_required = true;
            }
            break;
          }
        }
      }
    } else {
      LOG(DEBUG) << "applet does not exist";
      update_required = true;
    }

    if (update_required && all_scripts_info[i].load_script_exists) {
      load_required = true;
      // check if ELF is already present
      // Assuming existing installed_elf_aid is different
      // from the ELF AID we are updating to
      for (auto matching_elf : getstatus_response[k].matching_elfs) {
        if (load_script_elf_aid == matching_elf.elf_aid_complete) {
          LOG(INFO) << "ELF is already available in eSE: "
                    << all_scripts_info[i].load_script.script_path;
          load_required = false;
          break;
        }
      }
    }
    if (update_required) {
      // if update_required is true for atleast one applet
      *update_req = true;
    }
    if (load_required) {
      *load_req = true;
    }
    all_scripts_info[i].update_required = update_required;
    all_scripts_info[i].pre_load_required = load_required;

    // Build table row
    std::ostringstream row;
    row << "| " << std::left << std::setw(FIRST_COL_WIDTH)
        << toString(getstatus_response[k].applet_aid_partial) << "| "
        << std::setw(OTHER_COL_WIDTH) << toString(update_script_elf_ver) << "| "
        << std::setw(OTHER_COL_WIDTH) << toString(installed_elf_version) << "|";
    rows.push_back(row.str());
  }
}

// Local helper function to parse GetStatus script response
void ParseResponseLocal(GetStatusResponseType resp_type,
                        struct GetStatusResponse& temp,
                        std::vector<uint8_t>& getstatus_resp_vec) {
  LOG(DEBUG) << "resp_type is " << resp_type;
  if (resp_type == GetStatusResponseType::INSTANCE_DATA) {
    uint16_t offset = 0, total_len = 0;
    if (getstatus_resp_vec[offset] == 0xE3) {
      LOG(DEBUG) << "parsing first type of response";
      offset = offset + 2;
    } else {
      LOG(ERROR) << __FUNCTION__ << "wrong response";
      return;
    }
    while (offset < getstatus_resp_vec.size() - 4) {
      if (getstatus_resp_vec[offset] == 0x4F) {
        // Complete instance AID
        offset += 1;
        uint16_t aid_len = getstatus_resp_vec[offset];
        std::vector<uint8_t> instance_aid_complete(
            &(getstatus_resp_vec[offset + 1]),
            &(getstatus_resp_vec[offset + 1]) + aid_len);
        offset = offset + 1 + aid_len;
        LOG(DEBUG) << "parsed instance_aid_complete: "
                   << toString(instance_aid_complete);
        temp.instance_aid_complete = instance_aid_complete;
      } else if (getstatus_resp_vec[offset] == 0xC4) {
        offset += 1;
        uint16_t associated_elf_aid_len = getstatus_resp_vec[offset];
        std::vector<uint8_t> associated_elf_aid(
            &(getstatus_resp_vec[offset + 1]),
            &(getstatus_resp_vec[offset + 1]) + associated_elf_aid_len);
        offset = offset + 1 + associated_elf_aid_len;
        temp.associated_elf_aid = associated_elf_aid;
        LOG(DEBUG) << "parsed associated_elf_aid: "
                   << toString(associated_elf_aid);
      }
    }
  } else if (resp_type == GetStatusResponseType::MATCHING_ELF_DATA) {
    // parse response for matching ELF AID + (module_aids) + corresponding ELF
    // version
    uint16_t offset = 0;
    if (getstatus_resp_vec[offset] == 0xE3) {
      LOG(DEBUG) << "parsing second type of response";
      /*offset = offset + 2;*/
    } else {
      LOG(ERROR) << "unknown response received";
    }
    while (offset < getstatus_resp_vec.size() - 4) {
      if (getstatus_resp_vec[offset] == 0xE3) {
        struct MatchingELF matching_elf;
        memset(&matching_elf, 0, sizeof(struct MatchingELF));
        LOG(DEBUG) << "parse E3 Tag";
        offset += 1;
        uint16_t tagE3Len = getstatus_resp_vec[offset];
        offset += 1;
        uint16_t current_offset = offset;
        while ((offset - current_offset) < (tagE3Len)) {
          if (getstatus_resp_vec[offset] == 0x4F) {
            LOG(DEBUG) << "parse 4F Tag";
            offset += 1;
            uint16_t elf_aid_len = getstatus_resp_vec[offset];
            std::vector<uint8_t> elf_aid_complete(
                &(getstatus_resp_vec[offset + 1]),
                &(getstatus_resp_vec[offset + 1]) + elf_aid_len);
            offset += elf_aid_len + 1;
            LOG(DEBUG) << "ELFAID: " << toString(elf_aid_complete);
            matching_elf.elf_aid_complete = elf_aid_complete;
          } else if (getstatus_resp_vec[offset] == 0x84) {
            LOG(DEBUG) << "parse module AIDs";
            offset += 1;
            uint16_t module_aid_len = getstatus_resp_vec[offset];
            std::vector<uint8_t> module_aid_complete(
                &(getstatus_resp_vec[offset + 1]),
                &(getstatus_resp_vec[offset + 1]) + module_aid_len);
            LOG(DEBUG) << "module_aid: " << toString(module_aid_complete);
            matching_elf.module_aids.push_back(module_aid_complete);
            offset += module_aid_len + 1;
          } else if (getstatus_resp_vec[offset] == 0xCE) {
            LOG(DEBUG) << "parse ELF version";
            offset += 1;
            uint16_t elf_ver_len = getstatus_resp_vec[offset];
            std::vector<uint8_t> elf_version(
                &(getstatus_resp_vec[offset + 1]),
                &(getstatus_resp_vec[offset + 1]) + elf_ver_len);
            LOG(DEBUG) << "elf_version: " << toString(elf_version);
            offset += elf_ver_len + 1;
            matching_elf.elf_version = elf_version;
            temp.matching_elfs.push_back(matching_elf);
          }
        }
      }
    }
  }
}

// Process GetStatus script response
bool ParseResponse(uint8_t* respBuffer, int32_t respBuffersize) {
  if (exe_state == ExecutionState::GET_STATUS) {
    bool response_processed = false;
    bool applet_exists = true;
    // proceed only if this is GetStatus Response
    if (respBuffersize >= 2 && respBuffer[0] == 0x6A && respBuffer[1] == 0x88) {
      // case when this is fresh install of this applet
      LOG(DEBUG) << "Data_not_found received ";
      applet_exists = false;
    } else if (respBuffer[0] != 0xE3) {
      return true;
    }
    std::vector<uint8_t> resp_vec(respBuffer, respBuffer + respBuffersize);
    LOG(DEBUG) << "getstatus_response size is: " << getstatus_response.size();
    for (auto& current_entry : getstatus_response) {
      // parse response for application data Tag: E3-4F-84-CE
      if (!current_entry.matching_elf_data_recvd) {
        if (!current_entry.instance_data_recvd) {
          applet_exists = false;
        }
        // Look for matching ELFs
        ParseResponseLocal(GetStatusResponseType::MATCHING_ELF_DATA,
                           current_entry, resp_vec);
        current_entry.matching_elf_data_recvd = true;
        response_processed = true;
        break;
      }
    }
    if (!response_processed) {
      // parse response for application data E3 Tag - 4FC4
      if (getstatus_response.size() <
          getstatus_script.applet_aids_partial.size()) {
        struct GetStatusResponse temp;
        memset(&temp, 0, sizeof(struct GetStatusResponse));
        if (applet_exists) {
          ParseResponseLocal(GetStatusResponseType::INSTANCE_DATA, temp,
                             resp_vec);
          temp.instance_data_recvd = true;
        }
        temp.applet_aid_partial =
            getstatus_script.applet_aids_partial[getstatus_response.size()];
        temp.matching_elf_data_recvd = false;
        response_processed = true;
        getstatus_response.push_back(temp);
      }
    }
    return true;
  }
  if (respBuffersize == 2 && respBuffer[0] == 0x6A && respBuffer[1] == 0x88) {
    // this response is not expected during non getstatus script execution
    return false;
  }
  return true;
}

// Set execution state to determine type of script currently
// under execution
void SetScriptExecutionState(ExecutionState script_exe_state) {
  if (exe_state == ExecutionState::GET_STATUS) {
    LOG(INFO) << "Reset getstatus_response";
    getstatus_response.clear();
  }
  exe_state = script_exe_state;
}

// Local helper function to parse Authentication frame signature
// AuthFrame signature uniquely identifies a given sems script
void ParseAuthFrameSignature(const std::string& auth_frame_string,
                             std::vector<uint8_t>& auth_frame_sign) {
  uint8_t read_byte;
  const uint16_t size_ePK_SP_ENC = 65;
  const uint16_t size_E_K_K1 = 16;
  const uint16_t size_SHA256 = 32;

  std::vector<uint8_t> auth_frame;
  for (int x = 0; x < auth_frame_string.size();) {
    SSCANF_BYTE(auth_frame_string.c_str() + x, "%2X", &read_byte);
    auth_frame.push_back(read_byte);
    x = x + 2;
  }
  LOG(DEBUG) << toString(auth_frame);
  // extract signature from auth frame
  int32_t pLen = 0;
  // tag60
  uint32_t offset = 0;
  uint8_t len_byte = Numof_lengthbytes(&auth_frame[offset + 1], &pLen);
  offset = offset + 1 + len_byte;
  // tag41
  len_byte = Numof_lengthbytes(&auth_frame[offset + 1], &pLen);
  offset = offset + 1 + len_byte;
  offset = offset + size_ePK_SP_ENC + size_E_K_K1 + size_SHA256;
  if (auth_frame[offset] == 0x30) {
    LOG(DEBUG) << "Auth frame signature found";
    len_byte = Numof_lengthbytes(&auth_frame[offset + 1], &pLen);
    LOG(DEBUG) << "len_byte is " << static_cast<uint32_t>(len_byte)
               << " and length is " << pLen;

    auth_frame_sign.assign(&auth_frame[offset + 1 + len_byte],
                           &auth_frame[offset + 1 + len_byte] + pLen);
  }
}

// Checks and throws error for duplicate metadata entry
bool IsDuplicateEntry(auto& metafields, std::string fieldtype) {
  if (metafields.find(fieldtype) == metafields.end()) {
    metafields[fieldtype] = true;
    return false;
  } else {
    LOG(ERROR) << "Duplicate metadata field: " << fieldtype << " encountered";
    return true;
  }
}

// Verifies the presence of mandatory metadata fields
bool mandatoryMetaFieldsPresent(const auto& available_metafields,
                                const auto& mandatory_fields) {
  for (const auto& item : mandatory_fields) {
    auto search = available_metafields.find(item);
    if (search == available_metafields.end() || search->second != true) {
      LOG(ERROR) << "Missing metadata field: " << item
                 << " for LOAD/UPDATE script";
      return false;
    }
  }
  return true;
}

// Helper function to convert Hex string to byte array
std::vector<uint8_t> hexStringtoBytes(const auto& hex_string) {
  uint8_t read_buf = 0x00;
  std::vector<uint8_t> result;
  for (int x = 0; x < hex_string.size();) {
    SSCANF_BYTE(hex_string.c_str() + x, "%2X", &read_buf);
    result.push_back(read_buf);
    x = x + 2;
  }
  return result;
}

// Parses metadata section for each script
ParseMetadataError ParseSemsMetadata(const char* path) {
  std::ifstream file(path);
  if (!file.is_open()) {
    LOG(ERROR) << "Failed to open file: " << path << "  errno " << errno;
    return ParseMetadataError::FILE_IO_ERROR;
  }
  if (!file.good()) {
    LOG(WARNING) << "rdstate:" << file.rdstate();
    file.clear();
    if (!file.good()) {
      LOG(ERROR) << "file stream " << path
                 << " is corrupted. rdstate:" << file.rdstate();
      file.close();
      return ParseMetadataError::FILE_IO_ERROR;
    }
  }
  LOG(DEBUG) << "ParseSemsMetadata: " << path;
  std::vector<std::pair<std::string, std::pair<std::string, std::streampos>>>
      metadata;
  std::string line;
  uint8_t auth_frame_number = 0;

  // A SEMS script starts with Certificate Frame(7F21) and uniquley idenitified
  // using AUTH Frame(60) In case there are multiple scripts embedded within one
  // file, record AUTH frame and corresponding offset of 7F21 to identify which
  // script to run in case of tear
  std::streampos line_start_offset = 0, script_start_offset = 0;

  while (file) {
    line_start_offset = file.tellg();
    if (line_start_offset == -1) {
      LOG(ERROR) << "Failed to read current position in file. errno: " << errno;
      file.close();
      return ParseMetadataError::FILE_IO_ERROR;
    }
    // Read the file line by line
    if (!std::getline(file, line)) {
      break;
    }
    if (line.rfind("%%%", 0) == 0) {  // Check if line starts with %%%
      std::istringstream iss(line);
      std::string delim, key, value;

      // Parse the key and value
      iss >> delim >> key >> value;
      key = trim(key);
      value = trim(value);

      metadata.push_back(
          std::make_pair(key, std::make_pair(value, std::streampos(-1))));
    } else if (line.rfind("7f21", 0) == 0) {
      script_start_offset = line_start_offset;
    } else if (line.rfind("60", 0) == 0) {
      std::string key = "AUTH_FRAME" + std::to_string(auth_frame_number);
      trim(line);
      metadata.push_back(
          std::make_pair(key, std::make_pair(line, script_start_offset)));
    }
  }

  file.close();

  if (metadata.size() == 0) {
    return ParseMetadataError::MISSING_METADATA;
  }

  SemsScriptType script_type = INVALID_SCRIPT;
  // Find script type first
  for (int i = 0; i < metadata.size(); i++) {
    if (metadata[i].first == "SEMSType") {
      uint8_t current_byte;
      SSCANF_BYTE(metadata[0].second.first.c_str(), "%2X", &current_byte);
      script_type = (SemsScriptType)current_byte;
      break;
    }
  }

  std::unordered_map<std::string, bool> load_update_script_metafields;
  std::unordered_map<std::string, bool> getstatus_script_metafields;

  struct LoadUpdateScriptMetaInfo load_update_script_temp;
  memset(&load_update_script_temp, 0, sizeof(struct LoadUpdateScriptMetaInfo));

  for (int i = 0; i < metadata.size(); i++) {
    if (script_type == SemsScriptType::LOAD_SCRIPT ||
        script_type == SemsScriptType::UPDATE_SCRIPT) {
      const std::string& key = metadata[i].first;

      if (IsDuplicateEntry(load_update_script_metafields, key)) {
        return ParseMetadataError::DUPLICATE_METADATA_FIELD;
      }
      if (key == "AppletAID") {
        load_update_script_temp.applet_aid_partial =
            hexStringtoBytes(metadata[i].second.first);
      }
      if (key == "ELFAID") {
        load_update_script_temp.elf_aid_complete =
            hexStringtoBytes(metadata[i].second.first);
      }
      if (key == "ELFVersion") {
        load_update_script_temp.elf_version =
            hexStringtoBytes(metadata[i].second.first);
      }
      if (key == "ELFBaseVersion") {
        load_update_script_temp.elf_base_version =
            hexStringtoBytes(metadata[i].second.first);
      }
      if (key == "MinVolatileMemory") {
        try {
          load_update_script_temp.mem_req.min_volatile_memory_bytes =
              static_cast<uint32_t>(
                  std::stoul(metadata[i].second.first.c_str(), nullptr, 16));
        } catch (const std::invalid_argument& e) {
          LOG(ERROR) << "MinVolatileMemory: value is not a valid hex number";
          return ParseMetadataError::INVALID_HEX_FIELD;
        }
      }
      if (key == "MinNonVolatileMemory") {
        try {
          load_update_script_temp.mem_req.min_non_volatile_memory_bytes =
              static_cast<uint32_t>(
                  std::stoul(metadata[i].second.first.c_str(), nullptr, 16));
        } catch (const std::invalid_argument& e) {
          LOG(ERROR) << "MinNonVolatileMemory: value is not a valid hex number";
          return ParseMetadataError::INVALID_HEX_FIELD;
        }
      }
      if (key == "PlatformID") {
        uint8_t read_buf = 0x00;
        SSCANF_BYTE(metadata[i].second.first.c_str(), "%2X", &read_buf);
        load_update_script_temp.platform_id = read_buf;
      }
      if (key == "SEMSType") {
        load_update_script_temp.script_type = script_type;
        load_update_script_temp.script_path = path;
      }
      if (!key.compare(0, strlen("AUTH_FRAME"), "AUTH_FRAME")) {
        std::string auth_frame_string = metadata[i].second.first;
        std::streampos script_offset = metadata[i].second.second;
        std::vector<uint8_t> auth_frame_sign;
        ParseAuthFrameSignature(std::move(auth_frame_string), auth_frame_sign);
        load_update_script_temp.signatures.push_back(
            std::make_pair(auth_frame_sign, script_offset));
      }
    }
    if (script_type == SemsScriptType::GET_STATUS_SCRIPT) {
      const std::string& key = metadata[i].first;

      if (IsDuplicateEntry(getstatus_script_metafields, key)) {
        return ParseMetadataError::DUPLICATE_METADATA_FIELD;
      }
      if (key == "SEMSType") {
        getstatus_script.script_type = script_type;
        getstatus_script.script_path = path;
      }
      if (!key.compare(0, strlen("AppletAID"), "AppletAID")) {
        getstatus_script.applet_aids_partial.push_back(
            hexStringtoBytes(metadata[i].second.first));
      }
      if (!key.compare(0, strlen("AUTH_FRAME"), "AUTH_FRAME")) {
        std::string auth_frame_string = metadata[i].second.first;
        std::vector<uint8_t> auth_frame_signature;
        ParseAuthFrameSignature(std::move(auth_frame_string),
                                auth_frame_signature);
        getstatus_script.signature = auth_frame_signature;
      }
    }
  }

  if (script_type == SemsScriptType::LOAD_SCRIPT ||
      script_type == SemsScriptType::UPDATE_SCRIPT) {
    if (!mandatoryMetaFieldsPresent(
            load_update_script_metafields,
            MANDATORY_METADATA_FIELDS_LOAD_UPDATE_SCRIPT)) {
      return ParseMetadataError::MISSING_METADATA_FIELD;
    }
    load_update_script.push_back(load_update_script_temp);
  } else if (script_type == SemsScriptType::GET_STATUS_SCRIPT) {
    if (!mandatoryMetaFieldsPresent(
            getstatus_script_metafields,
            MANDATORY_METADATA_FIELDS_GETSTATUS_SCRIPT)) {
      return ParseMetadataError::MISSING_METADATA_FIELD;
    }
  } else {
    return ParseMetadataError::INVALID_SEMS_TYPE;
  }
  return ParseMetadataError::SUCCESS;
}

void PrintAllParsedMetadata() {
  LOG(INFO) << "Display parsed GETSTATUS scripts info";
  LOG(INFO) << "script_type:" << getstatus_script.script_type;
  LOG(INFO) << "script_path:" << getstatus_script.script_path;
  LOG(INFO) << "signature:" << toString(getstatus_script.signature);
  for (int i = 0; i < getstatus_script.applet_aids_partial.size(); i++) {
    LOG(INFO) << "AID: " << toString(getstatus_script.applet_aids_partial[i]);
  }

  LOG(INFO) << "Display parsed update scripts info";
  LOG(INFO) << "=======================================================";
  for (int i = 0; i < load_update_script.size(); i++) {
    LOG(INFO) << "script_path: " << load_update_script[i].script_path;
    LOG(INFO) << "script_type: " << load_update_script[i].script_type;
    LOG(INFO) << "applet_aid_partial:"
              << toString(load_update_script[i].applet_aid_partial);
    LOG(INFO) << "elf_aid_complete:"
              << toString(load_update_script[i].elf_aid_complete);
    LOG(INFO) << "elf_version:" << toString(load_update_script[i].elf_version);
    for (int count = 0; count < load_update_script[i].signatures.size();
         count++) {
      LOG(INFO) << "signature_" << count << ": "
                << toString(load_update_script[i].signatures[count].first);
      LOG(INFO) << "offset_" << count << ": "
                << load_update_script[i].signatures[count].second;
    }
    LOG(INFO) << "PlatformID: " << std::hex << std::setw(2) << std::setfill('0')
              << (load_update_script[i].platform_id & 0xFF);
    LOG(INFO) << "";
  }
  LOG(INFO) << "=======================================================";
}
