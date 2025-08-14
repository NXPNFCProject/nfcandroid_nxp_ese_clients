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

#include <SEConnection.h>
#include <SEUpdaterClient.h>
#include <ScriptMetadataParser.h>
#include <Utils.h>

#include <android-base/logging.h>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <vector>

std::vector<uint8_t> card_manager_aid = {0xA0, 0x00, 0x00, 0x01,
                                         0x51, 0x00, 0x00, 0x00};

// Helper function to safely read a uint32_t from iterator
bool readUint32(const std::vector<uint8_t>::const_iterator& it,
                const std::vector<uint8_t>::const_iterator& end,
                uint32_t& result) {
  if (std::distance(it, end) < 4) {
    LOG(ERROR) << "Insufficient bytes for uint32_t";
    return false;
  }
  result = (*it << 24) | (*(it + 1) << 16) | (*(it + 2) << 8) | *(it + 3);
  return true;
}

// Parses memory response from secure element using iterators
bool parseMemoryResponse(const std::vector<uint8_t>& ese_mem_data_all,
                         struct eSEAvailableMemory& ese_memory_parsed) {
  constexpr size_t kMinResponseSize = 43;
  constexpr uint16_t kStatusSuccess = 0x9000;

  if (ese_mem_data_all.size() < kMinResponseSize) {
    LOG(ERROR) << "Response too short: " << ese_mem_data_all.size()
               << "bytes, expected >=" << kMinResponseSize;
    return false;
  }

  if ((ese_mem_data_all[ese_mem_data_all.size() - 2] << 8 |
       ese_mem_data_all.back()) != kStatusSuccess) {
    LOG(ERROR) << "Invalid status word: " << toString(ese_mem_data_all);
    return false;
  }

  // Use iterator for sequential access
  auto it = ese_mem_data_all.cbegin();
  auto end = ese_mem_data_all.cend() - 2;  // ignore status word

  it += 2;  // Skip first two bytes (e.g., header)
  uint16_t tag = (*it++ << 8) | *it++;
  if (tag != AVL_MEMORY_TAG) {
    LOG(ERROR) << "Invalid tag: " << std::hex << std::uppercase << tag
               << ", expected 0x" << AVL_MEMORY_TAG;
    return false;
  }

  // Check length (1 byte)
  uint8_t length = *it++;

  for (; it != end;) {
    uint8_t tag = *it++;
    it++;  // Skip length byte

    uint32_t value = 0;
    if (!readUint32(it, end, value)) {
      return false;
    }
    it += 4;  // Advance past the 4-byte value

    switch (tag) {
      case MEM_TAG_00:
        ese_memory_parsed.tag_00 = value;
        break;
      case MEM_TAG_01:
        ese_memory_parsed.tag_01 = value;
        break;
      case MEM_TAG_02:
        ese_memory_parsed.tag_02 = value;
        break;
      case MEM_TAG_03:
        ese_memory_parsed.tag_03 = value;
        break;
      case MEM_TAG_07:
        ese_memory_parsed.tag_07 = value;
        break;
      case MEM_TAG_08:
        ese_memory_parsed.tag_08 = value;
        break;
      default:
        LOG(DEBUG) << "unused TAG:" << std::hex << tag;
    }
  }
  return true;
}

std::vector<uint8_t> getAvailableMemoryFromSE() {
  std::vector<uint8_t> get_avl_memory_resp;
  if (InitializeConnection() == SESTATUS_OK) {
    std::vector<uint8_t> select_resp;
    int8_t channel_num = -1;
    SEConnection::getInstance().transport_->openChannel(
        card_manager_aid, channel_num, select_resp);

    if (channel_num != -1) {
      LOG(INFO) << "AID Select Response: " << toString(select_resp);
      // Get Available Memory C-APDU
      std::vector<uint8_t> get_avl_memory_cmd = {0x80, 0xCA, 0x00, 0xFE,
                                                 0x02, 0xDF, 0x25};
      get_avl_memory_cmd[0] |= channel_num;
      auto status = SEConnection::getInstance().transport_->sendData(
          get_avl_memory_cmd, get_avl_memory_resp);
      if (status) {
        // cmd transmitted succesfully
        LOG(DEBUG) << "GetAvailableMemory RAPDU:"
                   << toString(get_avl_memory_resp);
      } else {
        LOG(ERROR) << "Failed to send GetAvailableMemory C-APDU";
      }
      status =
          SEConnection::getInstance().transport_->closeChannel(channel_num);
    } else {
      LOG(ERROR) << "Failed to open Channel to to cardManager";
    }
  }
  return get_avl_memory_resp;
}

bool hasSufficientESEMemoryForScript(
    const struct LoadUpdateScriptMetaInfo& current_script) {
  bool result = true;
  struct eSEAvailableMemory ese_memory_parsed = {0};
  std::vector<uint8_t> ese_memory_data = getAvailableMemoryFromSE();

  // Perform memory check only if getAvailableMemory cmd returns successful resp
  if (!ese_memory_data.empty() &&
      parseMemoryResponse(ese_memory_data, ese_memory_parsed)) {
    auto avl_nvm_bytes = ese_memory_parsed.tag_00;
    auto avl_ram_bytes = ese_memory_parsed.tag_01;

    if (current_script.mem_req.min_volatile_memory_bytes > avl_ram_bytes ||
        current_script.mem_req.min_non_volatile_memory_bytes > avl_nvm_bytes) {
      LOG(ERROR) << "Insufficient memory for script "
                 << current_script.script_path << "RAM " << avl_ram_bytes << "/"
                 << current_script.mem_req.min_volatile_memory_bytes << ", NVM "
                 << avl_nvm_bytes << "/"
                 << current_script.mem_req.min_non_volatile_memory_bytes;
      result = false;
    }
  }
  return result;
}

// Helper function to convert byte array to string
std::string toString(const std::vector<uint8_t>& vec) {
  std::ostringstream os;
  os << "{";
  for (auto& c : vec) {
    os << std::hex << std::setfill('0') << std::uppercase << std::setw(2)
       << (0xFF & c);
  }
  os << "}";
  return os.str();
}
