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
#endif
#endif /* ESE_UPDATE_2_H_ */
