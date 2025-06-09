/*******************************************************************************
 *
 *  Copyright 2018-2020, 2023,2025 NXP
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
#ifndef ESE_UPDATE_2_H_
#define ESE_UPDATE_2_H_

#include <string>
#ifdef NXP_BOOTTIME_UPDATE
#include "eSEClientIntf.h"
#define SESTATUS_OK SESTATUS_SUCCESS
#else
typedef enum {
  SESTATUS_OK = (0x0000),
  SESTATUS_FAILED = (0x0003),
  SESTATUS_FILE_NOT_FOUND = (0x0005)
} SESTATUS;

typedef enum {
  ESE_UPDATE_COMPLETED = 0,
  ESE_UPDATE_STARTED,
  ESE_LS_UPDATE_REQUIRED,
  ESE_LS_UPDATE_COMPLETED
} ese_update_state_t;
#endif

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
 * Checks and executes LOAD type Sems Script if required
 */
SESTATUS PrepareUpdate(const std::string& script_dir_path,
                       bool retry_load = false);

/**
 * Checks and executes UPDATE type Sems Script if required
 * only during early boot
 */
void PerformUpdate(const std::string& script_dir_path);

/**
 * Retries Prepare Update in case it was teared/failed
 */
void RetryPrepareUpdate(const std::string& script_dir_path);

/**
 * Logs Version info from eSE and from Update package for each applet
 */
void LogVersionInfo(const std::string& script_dir_path);
#ifdef NXP_BOOTTIME_UPDATE
/**
 * Legacy method for checking if update is required
 */
void checkEseClientUpdate();

/**
 * Legacy method for performing Update
 */
SESTATUS perform_eSEClientUpdate();

/**
 * Thread handler function for performing update
 */
void eSEClientUpdate_SE_Thread();

/**
 * Function to set current state
 */
void seteSEClientState(uint8_t state);
/**
 * Retrieve metrics about the available memory in SecureElement.
 */
std::vector<uint8_t> getAvailableMemoryFromSE();
#endif
#endif /* ESE_UPDATE_2_H_ */
