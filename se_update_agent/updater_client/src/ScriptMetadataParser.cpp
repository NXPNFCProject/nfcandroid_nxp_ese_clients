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

#define MIN_METADATA_FIELDS_LOAD_UPDATE_SCRIPT 5
#define MIN_METADATA_FIELDS_GETSTATUS_SCRIPT 2

#define FIRST_COL_WIDTH 40
#define OTHER_COL_WIDTH 20

void PrintAllParsedMetadata();
std::vector<struct LoadUpdateScriptMetaInfo> load_update_script;
std::vector<struct SemsScriptInfo> all_scripts_info;
struct GetStatusScriptMetaInfo getstatus_script;
std::vector<struct GetStatusResponse> getstatus_response;

ExecutionState exe_state;

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

int SSCANF_BYTE(const char* buf, const char* format, void* pVal) {
  int Result = 0;

  if ((NULL != buf) && (NULL != format) && (NULL != pVal)) {
    unsigned int dwVal;
    unsigned char* pTmp = (unsigned char*)pVal;
    Result = sscanf(buf, format, &dwVal);

    (*pTmp) = (unsigned char)(dwVal & 0x000000FF);
  }
  return Result;
}

// Function to trim leading and trailing whitespace
std::string trim(const std::string& str) {
  size_t first = str.find_first_not_of(' ');
  if (first == std::string::npos) return "";
  size_t last = str.find_last_not_of(' ');
  return str.substr(first, last - first + 1);
}

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

  for (int i = 0; i < getstatus_script.applet_aids_partial.size(); i++) {
    std::vector<uint8_t> partial_aid = getstatus_script.applet_aids_partial[i];
    LOG(DEBUG) << "partial_aid: " << toString(partial_aid);

    struct SemsScriptInfo temp;
    memset(&temp, 0, sizeof(struct SemsScriptInfo));
    temp.applet_aid_partial = partial_aid;
    for (int x = 0; x < load_update_script.size(); x++) {
      if (temp.applet_aid_partial == load_update_script[x].applet_aid_partial) {
        if (load_update_script[x].script_type == SemsScriptType::LOAD_SCRIPT) {
          temp.load_script = load_update_script[x];
          temp.load_script_exists = true;
          LOG(DEBUG) << "load script exists";
        } else if (load_update_script[x].script_type ==
                   SemsScriptType::UPDATE_SCRIPT) {
          temp.update_script = load_update_script[x];
          temp.update_script_exists = true;
          LOG(DEBUG) << "update script exists";
        }
      }
    }
    if (temp.update_script_exists) {
      all_scripts_info.push_back(temp);
    }
  }
  return ParseMetadataError::SUCCESS;
}

ParseMetadataError FilterScriptsForChiptype(std::vector<uint8_t>& chip_type) {
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
  LOG(INFO) << "Platform/ChipID is: " << p_id;
  std::vector<struct SemsScriptInfo> temp_all_scripts_info;

  for (auto& script : all_scripts_info) {
    bool script_invalid = false;
    switch (p_id) {
      case PlatformID::SN220_V3: {
        if (script.load_script_exists) {
          // AMD-H based Update is not supported for SN220_V3
          LOG(WARNING)
              << "LOAD_SCRIPT Type is not supported for chiptype:SN220_V3";
          script_invalid = true;
          return ParseMetadataError::INVALID_SEMS_TYPE;
        } else {
          script_invalid |=
              script.update_script_exists
                  ? (script.update_script.platform_id != PlatformID::SN220_V3)
                  : 0;
        }
      } break;
      case PlatformID::SN220_V5:
        script_invalid =
            script.load_script_exists
                ? (script.load_script.platform_id != PlatformID::SN220_V5)
                : 0;
        script_invalid |=
            script.update_script_exists
                ? (script.update_script.platform_id != PlatformID::SN220_V5)
                : 0;
        if (script_invalid) {
          LOG(INFO) << "Script is invalid for chiptype:SN220_V5";
        }
        break;
      case PlatformID::SN300:
      case PlatformID::SN330:
        script_invalid =
            script.load_script_exists
                ? (script.load_script.platform_id != PlatformID::SN300 &&
                   script.load_script.platform_id != PlatformID::SN330)
                : 0;
        script_invalid |=
            script.update_script_exists
                ? (script.update_script.platform_id != PlatformID::SN300 &&
                   script.update_script.platform_id != PlatformID::SN330)
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
      temp_all_scripts_info.push_back(script);
    }
  }
  all_scripts_info.clear();
  all_scripts_info = temp_all_scripts_info;
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

void CheckLoad_Or_UpdateRequired(bool* load_req, bool* update_req) {
  for (int i = 0; i < all_scripts_info.size(); i++) {
    auto load_script_elf_aid = all_scripts_info[i].load_script.elf_aid_complete;
    auto load_script_elf_ver = all_scripts_info[i].load_script.elf_version;
    auto update_script_elf_ver = all_scripts_info[i].update_script.elf_version;
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
    if (all_scripts_info[i].load_script_exists) {
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
          LOG(INFO) << "Installed_elf_ver:"
                    << toString(matching_elf.elf_version);
          installed_elf_version = matching_elf.elf_version;
          if (update_script_elf_ver.size() == 2) {
            if (update_script_elf_ver[0] > matching_elf.elf_version[0] ||
                (update_script_elf_ver[0] == matching_elf.elf_version[0] &&
                 update_script_elf_ver[1] > matching_elf.elf_version[1])) {
              update_required = true;
              break;
            }
          }
        }
      }
    } else {
      LOG(DEBUG) << "applet does not exist";
      update_required = true;
    }
    if (update_required) {
      // if update_required is true for atleast one applet
      *update_req = true;
    }
    if (load_required) {
      *load_req = true;
    }
    LOG(INFO) << "AppletAID: "
              << toString(getstatus_response[k].applet_aid_partial);
    LOG(INFO) << "Update Pkg Version: " << toString(update_script_elf_ver);
    LOG(INFO) << "Installed Version: " << toString(installed_elf_version);
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
void SetScriptExecutionState(ExecutionState script_exe_state) {
  if (exe_state == ExecutionState::GET_STATUS) {
    LOG(INFO) << "Reset getstatus_response";
    getstatus_response.clear();
  }
  exe_state = script_exe_state;
}

void ParseAuthFrameSignature(const std::string auth_frame_string,
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
  LOG(DEBUG) << "auth frame size after trimming is:"
             << auth_frame_string.size();
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

bool IsDuplicateEntry(std::set<std::string>& metafields,
                      std::string fieldtype) {
  if (metafields.find(fieldtype) == metafields.end()) {
    metafields.insert(fieldtype);
    return false;
  } else {
    LOG(ERROR) << "Duplicate entry " << fieldtype << " encountered";
    return true;
  }
}

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
      LOG(INFO) << "File read completed";
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
      LOG(DEBUG) << "7F21 found, record script offset";
      script_start_offset = line_start_offset;
    } else if (line.rfind("60", 0) == 0) {
      LOG(DEBUG) << "Found auth frame";
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
  if (!strncmp(metadata[0].first.c_str(), "SEMSType", strlen("SEMSType"))) {
    uint8_t current_byte;
    SSCANF_BYTE(metadata[0].second.first.c_str(), "%2X", &current_byte);
    script_type = (SemsScriptType)current_byte;
  }

  std::set<std::string> load_update_script_metafields;
  std::set<std::string> getstatus_script_metafields;
  struct LoadUpdateScriptMetaInfo load_update_script_temp;
  memset(&load_update_script_temp, 0, sizeof(struct LoadUpdateScriptMetaInfo));

  for (int i = 0; i < metadata.size(); i++) {
    if (script_type == SemsScriptType::LOAD_SCRIPT ||
        script_type == SemsScriptType::UPDATE_SCRIPT) {
      if (!metadata[i].first.compare(0, strlen("AppletAID"), "AppletAID")) {
        uint8_t read_buf = 0x00;
        std::vector<uint8_t> partial_aid;
        for (int x = 0; x < metadata[i].second.first.size();) {
          SSCANF_BYTE(metadata[i].second.first.c_str() + x, "%2X", &read_buf);
          partial_aid.push_back(read_buf);
          x = x + 2;
        }
        load_update_script_temp.applet_aid_partial = partial_aid;
        if (IsDuplicateEntry(load_update_script_metafields, "AppletAID")) {
          return ParseMetadataError::DUPLICATE_METADATA_FIELD;
        }
      }
      if (!metadata[i].first.compare(0, strlen("ELFAID"), "ELFAID")) {
        uint8_t read_buf = 0x00;
        std::vector<uint8_t> elf_aid;
        for (int x = 0; x < metadata[i].second.first.size();) {
          SSCANF_BYTE(metadata[i].second.first.c_str() + x, "%2X", &read_buf);
          elf_aid.push_back(read_buf);
          x = x + 2;
        }
        load_update_script_temp.elf_aid_complete = elf_aid;
        if (IsDuplicateEntry(load_update_script_metafields, "ELFAID")) {
          return ParseMetadataError::DUPLICATE_METADATA_FIELD;
        }
      }
      if (!metadata[i].first.compare(0, strlen("ELFVersion"), "ELFVersion")) {
        uint8_t read_buf = 0x00;
        for (int x = 0; x < metadata[i].second.first.size();) {
          SSCANF_BYTE(metadata[i].second.first.c_str() + x, "%2X", &read_buf);
          load_update_script_temp.elf_version.push_back(read_buf);
          x = x + 2;
        }
        if (IsDuplicateEntry(load_update_script_metafields, "ELFVersion")) {
          return ParseMetadataError::DUPLICATE_METADATA_FIELD;
        }
      }
      if (!metadata[i].first.compare(0, strlen("MinVolatileMemory"),
                                     "MinVolatileMemory")) {
        try {
          load_update_script_temp.mem_req.min_volatile_memory_bytes =
              static_cast<uint32_t>(
                  std::stoul(metadata[i].second.first.c_str(), nullptr, 16));
        } catch (const std::invalid_argument& e) {
          LOG(ERROR) << "MinVolatileMemory: value is not a valid hex number";
          return ParseMetadataError::INVALID_HEX_FIELD;
        }
        if (IsDuplicateEntry(load_update_script_metafields,
                             "MinVolatileMemory")) {
          return ParseMetadataError::DUPLICATE_METADATA_FIELD;
        }
      }
      if (!metadata[i].first.compare(0, strlen("MinNonVolatileMemory"),
                                     "MinNonVolatileMemory")) {
        try {
          load_update_script_temp.mem_req.min_non_volatile_memory_bytes =
              static_cast<uint32_t>(
                  std::stoul(metadata[i].second.first.c_str(), nullptr, 16));
        } catch (const std::invalid_argument& e) {
          LOG(ERROR) << "MinNonVolatileMemory: value is not a valid hex number";
          return ParseMetadataError::INVALID_HEX_FIELD;
        }
        if (IsDuplicateEntry(load_update_script_metafields,
                             "MinNonVolatileMemory")) {
          return ParseMetadataError::DUPLICATE_METADATA_FIELD;
        }
      }
      if (!metadata[i].first.compare(0, strlen("PlatformID"), "PlatformID")) {
        uint8_t read_buf = 0x00;
        SSCANF_BYTE(metadata[i].second.first.c_str(), "%2X", &read_buf);
        load_update_script_temp.platform_id = read_buf;
        if (IsDuplicateEntry(load_update_script_metafields, "PlatformID")) {
          return ParseMetadataError::DUPLICATE_METADATA_FIELD;
        }
      }
      if (!metadata[i].first.compare(0, strlen("SEMSType"), "SEMSType")) {
        load_update_script_temp.script_type = script_type;
        load_update_script_temp.script_path = path;
        if (IsDuplicateEntry(load_update_script_metafields, "SEMSType")) {
          return ParseMetadataError::DUPLICATE_METADATA_FIELD;
        }
      }
      if (!metadata[i].first.compare(0, strlen("AUTH_FRAME"), "AUTH_FRAME")) {
        std::string auth_frame_string = metadata[i].second.first;
        std::streampos script_offset = metadata[i].second.second;
        std::vector<uint8_t> auth_frame_sign;
        ParseAuthFrameSignature(std::move(auth_frame_string), auth_frame_sign);
        LOG(DEBUG) << "frame signature is:" << toString(auth_frame_sign);
        load_update_script_temp.signatures.push_back(
            std::make_pair(auth_frame_sign, script_offset));
      }
    }
    if (script_type == SemsScriptType::GET_STATUS_SCRIPT) {
      if (!metadata[i].first.compare(0, strlen("SEMSType"), "SEMSType")) {
        getstatus_script.script_type = script_type;
        getstatus_script.script_path = path;
        if (IsDuplicateEntry(getstatus_script_metafields, "SEMSType")) {
          return ParseMetadataError::DUPLICATE_METADATA_FIELD;
        }
      }
      if (!metadata[i].first.compare(0, strlen("AppletAID"), "AppletAID")) {
        uint8_t read_buf = 0x00;
        std::vector<uint8_t> partial_aid;
        for (int x = 0; x < metadata[i].second.first.size();) {
          SSCANF_BYTE(metadata[i].second.first.c_str() + x, "%2X", &read_buf);
          partial_aid.push_back(read_buf);
          x = x + 2;
        }
        getstatus_script.applet_aids_partial.push_back(partial_aid);
        if (IsDuplicateEntry(getstatus_script_metafields, metadata[i].first)) {
          return ParseMetadataError::DUPLICATE_METADATA_FIELD;
        }
      }
      if (!metadata[i].first.compare(0, strlen("AUTH_FRAME"), "AUTH_FRAME")) {
        std::string auth_frame_string = metadata[i].second.first;
        std::vector<uint8_t> auth_frame_signature;
        ParseAuthFrameSignature(std::move(auth_frame_string),
                                auth_frame_signature);
        LOG(DEBUG) << "frame signature is:" << toString(auth_frame_signature);
        getstatus_script.signature = auth_frame_signature;
      }
    }
  }

  if (script_type == SemsScriptType::LOAD_SCRIPT ||
      script_type == SemsScriptType::UPDATE_SCRIPT) {
    if (load_update_script_metafields.size() <
        MIN_METADATA_FIELDS_LOAD_UPDATE_SCRIPT) {
      LOG(ERROR) << "Missing metadata field for LOAD/UPDATE script";
      return ParseMetadataError::MISSING_METADATA_FIELD;
    }
    load_update_script.push_back(load_update_script_temp);
  } else if (script_type == SemsScriptType::GET_STATUS_SCRIPT) {
    if (getstatus_script_metafields.size() <
        MIN_METADATA_FIELDS_GETSTATUS_SCRIPT) {
      LOG(ERROR) << "Missing metadata field for GET_STATUS script";
      return ParseMetadataError::MISSING_METADATA_FIELD;
    }
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
