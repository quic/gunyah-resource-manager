// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <inttypes.h>

#include <rm_types.h>

#include <guest_interface.h>
#include <random.h>
#include <resource-manager.h>

uint64_result_t
random_get_entropy64(void)
{
	uint64_result_t ret = { .e = ERROR_UNIMPLEMENTED };

	if (hyp_api_flags0_get_prng(&hyp_id.api_flags_0)) {
		gunyah_hyp_prng_get_entropy_result_t prng;
		do {
			prng = gunyah_hyp_prng_get_entropy(
				(count_t)sizeof(uint32_t) * 2U);
		} while (prng.error == ERROR_BUSY);

		ret.e = prng.error;
		if (ret.e == OK) {
			ret.r = (uint64_t)prng.data0;
			ret.r |= (uint64_t)prng.data1 << 32;
		}
	}

	return ret;
}
