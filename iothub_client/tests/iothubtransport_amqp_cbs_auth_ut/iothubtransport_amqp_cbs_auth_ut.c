// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>

void* real_malloc(size_t size)
{
	return malloc(size);
}

void real_free(void* ptr)
{
	free(ptr);
}

#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "testrunnerswitcher.h"
#include "azure_c_shared_utility/macro_utils.h"
#include "umock_c.h"
#include "umocktypes_charptr.h"
#include "umocktypes_stdint.h"
#include "umocktypes_bool.h"
#include "umock_c_negative_tests.h"
#include "umocktypes.h"
#include "umocktypes_c.h"

#define ENABLE_MOCKS
#include "iothub_transport_ll.h"
#include "azure_uamqp_c/cbs.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/umock_c_prod.h"
#include "azure_c_shared_utility/agenttime.h" 
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/sastoken.h"
#undef ENABLE_MOCKS

#include "iothubtransport_amqp_cbs_auth.h"

MOCKABLE_FUNCTION(, time_t, get_time, time_t*, currentTime);
MOCKABLE_FUNCTION(, double, get_difftime, time_t, stopTime, time_t, startTime);

static TEST_MUTEX_HANDLE g_testByTest;
static TEST_MUTEX_HANDLE g_dllByDll;


DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
	char temp_str[256];
	(void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s", ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
	ASSERT_FAIL(temp_str);
}


// Control parameters

#define TEST_DEVICE_ID                                    "my_device"
#define TEST_DEVICE_ID_STRING_HANDLE                      (STRING_HANDLE)0x4442
#define TEST_IOTHUB_HOST_FQDN                             "some.fqdn.com"
#define TEST_IOTHUB_HOST_FQDN_STRING_HANDLE               (STRING_HANDLE)0x4443
#define TEST_ON_STATE_CHANGED_CALLBACK_CONTEXT            (void*)0x4444
#define TEST_ON_ERROR_CALLBACK_CONTEXT                    (void*)0x4445
#define TEST_PRIMARY_DEVICE_ID                            "MUhT4tkv1auVqZFQC0lyuHFf6dec+ZhWCgCZ0HcNPuW="
#define TEST_PRIMARY_DEVICE_ID_STRING_HANDLE              (STRING_HANDLE)0x4446
#define TEST_SECONDARY_DEVICE_ID                          "WCgCZ0HcNPuWMUhTdec+ZhVqZFQC4tkv1auHFf60lyu="
#define TEST_SECONDARY_DEVICE_ID_STRING_HANDLE            (STRING_HANDLE)0x4447
#define TEST_USER_DEFINED_SAS_TOKEN                       "blablabla"
#define TEST_USER_DEFINED_SAS_TOKEN_STRING_HANDLE         (STRING_HANDLE)0x4448


static AUTHENTICATION_CONFIG global_auth_config;



// Auxiliary Functions

static void* saved_on_state_changed_callback_context;
static AUTHENTICATION_STATE saved_on_state_changed_callback_previous_state;
static AUTHENTICATION_STATE saved_on_state_changed_callback_new_state;
static void TEST_on_state_changed_callback(void* context, AUTHENTICATION_STATE previous_state, AUTHENTICATION_STATE new_state)
{
	saved_on_state_changed_callback_context = context;
	saved_on_state_changed_callback_previous_state = previous_state;
	saved_on_state_changed_callback_new_state = new_state;
}

static void* saved_on_error_callback_context;
static AUTHENTICATION_ERROR_CODE saved_on_error_callback_error_code;
static void TEST_on_error_callback(void* context, AUTHENTICATION_ERROR_CODE error_code)
{
	saved_on_error_callback_context = context;
	saved_on_error_callback_error_code = error_code;
}

typedef enum USE_DEVICE_KEYS_OR_SAS_TOKEN_OPTION_TAG
{
	USE_DEVICE_KEYS,
	USE_DEVICE_SAS_TOKEN
} USE_DEVICE_KEYS_OR_SAS_TOKEN_OPTION;

static AUTHENTICATION_CONFIG* get_auth_config(USE_DEVICE_KEYS_OR_SAS_TOKEN_OPTION credential_option)
{
	memset(&global_auth_config, 0, sizeof(AUTHENTICATION_CONFIG));
	global_auth_config.device_id = TEST_DEVICE_ID;

	if (credential_option == USE_DEVICE_KEYS)
	{
		global_auth_config.device_primary_key = TEST_PRIMARY_DEVICE_ID;
		global_auth_config.device_secondary_key = TEST_SECONDARY_DEVICE_ID;
	}
	else
	{
		global_auth_config.device_sas_token = TEST_USER_DEFINED_SAS_TOKEN;
	}

	global_auth_config.iothub_host_fqdn = TEST_IOTHUB_HOST_FQDN;
	global_auth_config.on_state_changed_callback = TEST_on_state_changed_callback;
	global_auth_config.on_state_changed_callback_context = TEST_ON_STATE_CHANGED_CALLBACK_CONTEXT;
	global_auth_config.on_error_callback = TEST_on_error_callback;
	global_auth_config.on_error_callback_context = TEST_ON_ERROR_CALLBACK_CONTEXT;

	return &global_auth_config;
}

static void set_expected_calls_for_authentication_create(AUTHENTICATION_CONFIG* config)
{
	EXPECTED_CALL(malloc(IGNORED_NUM_ARG));
	EXPECTED_CALL(memset(IGNORED_PTR_ARG, 0, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(3);
	STRICT_EXPECTED_CALL(STRING_construct(TEST_DEVICE_ID)).SetReturn(TEST_DEVICE_ID_STRING_HANDLE);

	if (config->device_sas_token != NULL)
	{
		STRICT_EXPECTED_CALL(STRING_construct(TEST_USER_DEFINED_SAS_TOKEN)).SetReturn(TEST_USER_DEFINED_SAS_TOKEN_STRING_HANDLE);
	}
	else
	{
		if (config->device_primary_key != NULL)
			STRICT_EXPECTED_CALL(STRING_construct(TEST_PRIMARY_DEVICE_KEY)).SetReturn(TEST_PRIMARY_DEVICE_KEY_STRING_HANDLE);
		
		if (config->device_secondary_key != NULL)
			STRICT_EXPECTED_CALL(STRING_construct(TEST_SECONDARY_DEVICE_KEY)).SetReturn(TEST_SECONDARY_DEVICE_KEY_STRING_HANDLE);
	}

	STRICT_EXPECTED_CALL(STRING_construct(TEST_IOTHUB_HOST_FQDN)).SetReturn(TEST_IOTHUB_HOST_FQDN_STRING_HANDLE);
}


// Function Hooks

static int saved_malloc_returns_count = 0;
static void* saved_malloc_returns[20];

static void* TEST_malloc(size_t size)
{
	saved_malloc_returns[saved_malloc_returns_count] = real_malloc(size);

	return saved_malloc_returns[saved_malloc_returns_count++];
}

static void TEST_free(void* ptr)
{
	int i, j;
	for (i = 0, j = 0; j < saved_malloc_returns_count; i++, j++)
	{
		if (saved_malloc_returns[i] == ptr) j++;

		saved_malloc_returns[i] = saved_malloc_returns[j];
	}

	if (i != j) saved_malloc_returns_count--;

	real_free(ptr);
}

static void reset_parameters()
{
	saved_malloc_returns_count = 0;
}


BEGIN_TEST_SUITE(iothubtransport_amqp_cbs_auth_ut)

TEST_SUITE_INITIALIZE(TestClassInitialize)
{
    TEST_INITIALIZE_MEMORY_DEBUG(g_dllByDll);
    g_testByTest = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(g_testByTest);

    umock_c_init(on_umock_c_error);

	int result = umocktypes_charptr_register_types();
	ASSERT_ARE_EQUAL(int, 0, result);
	result = umocktypes_stdint_register_types();
	ASSERT_ARE_EQUAL(int, 0, result);
    result = umocktypes_bool_register_types();
    ASSERT_ARE_EQUAL(int, 0, result);

}

TEST_SUITE_CLEANUP(TestClassCleanup)
{
    umock_c_deinit();

    TEST_MUTEX_DESTROY(g_testByTest);
    TEST_DEINITIALIZE_MEMORY_DEBUG(g_dllByDll);
}

TEST_FUNCTION_INITIALIZE(TestMethodInitialize)
{
    if (TEST_MUTEX_ACQUIRE(g_testByTest))
    {
        ASSERT_FAIL("our mutex is ABANDONED. Failure in test framework");
    }

    umock_c_reset_all_calls();

	reset_parameters();
}

TEST_FUNCTION_CLEANUP(TestMethodCleanup)
{
    TEST_MUTEX_RELEASE(g_testByTest);
}

// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_001: [If parameter `config` or `config->device_id` are NULL, authentication_create() shall fail and return NULL.]
TEST_FUNCTION(authentication_create_NULL_config)
{
	// arrange

	// act
	AUTHENTICATION_HANDLE handle = authentication_create(NULL);

	// assert
	ASSERT_IS_NULL(handle);

	// cleanup
}

// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_001: [If parameter `config` or `config->device_id` are NULL, authentication_create() shall fail and return NULL.]
TEST_FUNCTION(authentication_create_NULL_config_device_id)
{
	// arrange
	AUTHENTICATION_CONFIG* config = get_auth_config(USE_DEVICE_KEYS);
	config->device_id = NULL;

	// act
	AUTHENTICATION_HANDLE handle = authentication_create(config);

	// assert
	ASSERT_IS_NULL(handle);

	// cleanup
}

// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_002: [If device keys and SAS token are NULL, authentication_create() shall fail and return NULL.]
TEST_FUNCTION(authentication_create_NULL_config_device_keys_and_sas_token)
{
	// arrange
	AUTHENTICATION_CONFIG* config = get_auth_config(USE_DEVICE_KEYS);
	config->device_primary_key = NULL;
	config->device_secondary_key = NULL;
	config->device_sas_token = NULL;

	// act
	AUTHENTICATION_HANDLE handle = authentication_create(config);

	// assert
	ASSERT_IS_NULL(handle);

	// cleanup
}

// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_003: [If device keys and SAS token are both provided, authentication_create() shall fail and return NULL.]
TEST_FUNCTION(authentication_create_BOTH_config_device_keys_and_sas_token)
{
	// arrange
	AUTHENTICATION_CONFIG* config = get_auth_config(USE_DEVICE_KEYS);
	config->device_sas_token = TEST_USER_DEFINED_SAS_TOKEN;

	// act
	AUTHENTICATION_HANDLE handle = authentication_create(config);

	// assert
	ASSERT_IS_NULL(handle);

	// cleanup
}

// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_004: [If `config->iothub_host_fqdn` is NULL, authentication_create() shall fail and return NULL.]
TEST_FUNCTION(authentication_create_NULL_iothub_host_fqdn)
{
	// arrange
	AUTHENTICATION_CONFIG* config = get_auth_config(USE_DEVICE_KEYS);
	config->iothub_host_fqdn = NULL;

	// act
	AUTHENTICATION_HANDLE handle = authentication_create(config);

	// assert
	ASSERT_IS_NULL(handle);

	// cleanup
}

// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_005: [If `config->on_state_changed_callback` is NULL, authentication_create() shall fail and return NULL]
TEST_FUNCTION(authentication_create_NULL_on_state_changed_callback)
{
	// arrange
	AUTHENTICATION_CONFIG* config = get_auth_config(USE_DEVICE_KEYS);
	config->on_state_changed_callback = NULL;

	// act
	AUTHENTICATION_HANDLE handle = authentication_create(config);

	// assert
	ASSERT_IS_NULL(handle);

	// cleanup
}

// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_006: [authentication_create() shall allocate memory for a new authenticate state structure AUTHENTICATION_INSTANCE.]
// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_123: [authentication_create() shall initialize all fields of `instance` with 0 using memset().]
// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_008: [authentication_create() shall save a copy of `config->device_id` into the `instance->device_id`]
// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_010: [If `device_config->device_sas_token` is not NULL, authentication_create() shall save a copy into the `instance->device_sas_token`]
// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_012: [If provided, authentication_create() shall save a copy of `config->device_primary_key` into the `instance->device_primary_key`]
// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_014: [If provided, authentication_create() shall save a copy of `config->device_secondary_key` into `instance->device_secondary_key`]
// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_016: [If provided, authentication_create() shall save a copy of `config->iothub_host_fqdn` into `instance->iothub_host_fqdn`]
// Tests_SRS_IOTHUBTRANSPORT_AMQP_AUTH_09_024: [If no failure occurs, authentication_create() shall return a reference to the AUTHENTICATION_INSTANCE handle]
TEST_FUNCTION(authentication_create_DEVICE_KEYS_succeeds)
{
	// arrange
	AUTHENTICATION_CONFIG* config = get_auth_config(USE_DEVICE_KEYS);

	umock_c_reset_all_calls();
	set_expected_calls_for_authentication_create(config);

	// act
	AUTHENTICATION_HANDLE handle = authentication_create(config);

	// assert
	ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
	ASSERT_ARE_EQUAL(void_ptr, (void*)handle, (void*)saved_malloc_returns[0]);

	// cleanup
	authentication_destroy(handle);
}

END_TEST_SUITE(iothubtransport_amqp_cbs_auth_ut)
