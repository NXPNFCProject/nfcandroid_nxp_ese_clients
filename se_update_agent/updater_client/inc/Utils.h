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

#ifndef ESE_UPDATE_UTILS_H_
#define ESE_UPDATE_UTILS_H_

#include <unistd.h>
#include <iostream>
#include <vector>

struct eSEAvailableMemory {
  uint32_t tag_00;  // available persistent memory [System]
  uint32_t tag_01;  // available transient clear-on-reset memory [System]
  uint32_t tag_02;  // available transient clear-on-deselect memory [System]
  uint32_t tag_03;  // available number of indices in the index table [System]
  uint32_t tag_07;  // available transient system memory, excluding CGM reserves
                    // [System]
  uint32_t tag_08;  // available persistent system memory, excluding CGM
                    // reserves [System]
};

constexpr uint16_t AVL_MEMORY_TAG = 0xDF25;
constexpr uint8_t EXPECTED_LENGTH = 0x24;
constexpr uint8_t MEM_TAG_00 = 0x00;
constexpr uint8_t MEM_TAG_01 = 0x01;
constexpr uint8_t MEM_TAG_02 = 0x02;
constexpr uint8_t MEM_TAG_03 = 0x03;
constexpr uint8_t MEM_TAG_07 = 0x07;
constexpr uint8_t MEM_TAG_08 = 0x08;

/**
 * Function to get Available Memory from Secure Element
 */
std::vector<uint8_t> getAvailableMemoryFromSE();

/**
 * Returns true if Secure Element has sufficient memory to install/execute
 * the given SEMS script.
 */
bool hasSufficientESEMemoryForScript(
    const struct LoadUpdateScriptMetaInfo& current_script);

/**
 * Parses Secure Element available memory in eSEAvailableMemory struct form
 */
bool parseMemoryResponse(const std::vector<uint8_t>& ese_mem_data_all,
                         struct eSEAvailableMemory& ese_memory_parsed);

/**
 * Utility function to print vector contents
 */
std::string toString(const std::vector<uint8_t>& vec);
#endif
