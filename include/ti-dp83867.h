/*
 * (C) Copyright 2016
 * Texas Instruments Incorporated, <www.ti.com>
 *
 * Jean-Jacques Hiblot <jjhiblot@ti.com>
 */

#ifndef __TI_DP83867_H_
#define __TI_DP83867_H_

#include <dt-bindings/net/ti-dp83867.h>

#define DP83867_IO_MUX_CFG_IO_IMPEDANCE_MAX	0x0
#define DP83867_IO_MUX_CFG_IO_IMPEDANCE_MIN	0x1f

struct dp83867_private {
	int rx_id_delay;
	int tx_id_delay;
	int fifo_depth;
	int io_impedance;
};

void board_dp83867_init(struct dp83867_private *dp83867);

#endif /* __TI_DP83867_H_ */
