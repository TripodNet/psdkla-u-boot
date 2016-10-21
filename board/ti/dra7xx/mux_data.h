/*
 * (C) Copyright 2013
 * Texas Instruments Incorporated, <www.ti.com>
 *
 * Sricharan R	<r.sricharan@ti.com>
 * Nishant Kamat <nskamat@ti.com>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#ifndef _MUX_DATA_DRA7XX_H_
#define _MUX_DATA_DRA7XX_H_

#include <asm/arch/mux_dra7xx.h>

const struct pad_conf_entry dra71x_core_padconf_array[] = {
	{GPMC_AD0, (M3 | PIN_INPUT)},	/* gpmc_ad0.vout3_d0 */
	{GPMC_AD1, (M3 | PIN_INPUT)},	/* gpmc_ad1.vout3_d1 */
	{GPMC_AD2, (M3 | PIN_INPUT)},	/* gpmc_ad2.vout3_d2 */
	{GPMC_AD3, (M3 | PIN_INPUT)},	/* gpmc_ad3.vout3_d3 */
	{GPMC_AD4, (M3 | PIN_INPUT)},	/* gpmc_ad4.vout3_d4 */
	{GPMC_AD5, (M3 | PIN_INPUT)},	/* gpmc_ad5.vout3_d5 */
	{GPMC_AD6, (M3 | PIN_INPUT)},	/* gpmc_ad6.vout3_d6 */
	{GPMC_AD7, (M3 | PIN_INPUT)},	/* gpmc_ad7.vout3_d7 */
	{GPMC_AD8, (M3 | PIN_INPUT)},	/* gpmc_ad8.vout3_d8 */
	{GPMC_AD9, (M3 | PIN_INPUT)},	/* gpmc_ad9.vout3_d9 */
	{GPMC_AD10, (M3 | PIN_INPUT)},	/* gpmc_ad10.vout3_d10 */
	{GPMC_AD11, (M3 | PIN_INPUT)},	/* gpmc_ad11.vout3_d11 */
	{GPMC_AD12, (M3 | PIN_INPUT)},	/* gpmc_ad12.vout3_d12 */
	{GPMC_AD13, (M3 | PIN_INPUT)},	/* gpmc_ad13.vout3_d13 */
	{GPMC_AD14, (M3 | PIN_INPUT)},	/* gpmc_ad14.vout3_d14 */
	{GPMC_AD15, (M3 | PIN_INPUT)},	/* gpmc_ad15.vout3_d15 */
	{GPMC_A0, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a0.vout3_d16 */
	{GPMC_A1, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a1.vout3_d17 */
	{GPMC_A2, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a2.vout3_d18 */
	{GPMC_A3, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a3.vout3_d19 */
	{GPMC_A4, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a4.vout3_d20 */
	{GPMC_A5, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a5.vout3_d21 */
	{GPMC_A6, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a6.vout3_d22 */
	{GPMC_A7, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a7.vout3_d23 */
	{GPMC_A8, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a8.vout3_hsync */
	{GPMC_A9, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a9.vout3_vsync */
	{GPMC_A10, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a10.vout3_de */
	{GPMC_A11, (M14 | PIN_INPUT)},	/* gpmc_a11.gpio2_1 */
	{GPMC_A13, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* gpmc_a13.qspi1_rtclk */
	{GPMC_A14, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE)},	/* gpmc_a14.qspi1_d3 */
	{GPMC_A15, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE)},	/* gpmc_a15.qspi1_d2 */
	{GPMC_A16, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* gpmc_a16.qspi1_d0 */
	{GPMC_A17, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* gpmc_a17.qspi1_d1 */
	{GPMC_A18, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* gpmc_a18.qspi1_sclk */
	{GPMC_A19, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a19.mmc2_dat4 */
	{GPMC_A20, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a20.mmc2_dat5 */
	{GPMC_A21, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a21.mmc2_dat6 */
	{GPMC_A22, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a22.mmc2_dat7 */
	{GPMC_A23, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a23.mmc2_clk */
	{GPMC_A24, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a24.mmc2_dat0 */
	{GPMC_A25, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a25.mmc2_dat1 */
	{GPMC_A26, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a26.mmc2_dat2 */
	{GPMC_A27, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a27.mmc2_dat3 */
	{GPMC_CS1, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_cs1.mmc2_cmd */
	{GPMC_CS2, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE)},	/* gpmc_cs2.qspi1_cs0 */
	{GPMC_CS3, (M3 | PIN_INPUT_PULLUP)},	/* gpmc_cs3.vout3_clk */
	{VIN2A_CLK0, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE9)},	/* vin2a_clk0.vin2a_clk0 */
	{VIN2A_FLD0, (M14 | PIN_INPUT)},	/* vin2a_fld0.gpio3_30 */
	{VIN2A_HSYNC0, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE6)},	/* vin2a_hsync0.vin2a_hsync0 */
	{VIN2A_VSYNC0, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE9)},	/* vin2a_vsync0.vin2a_vsync0 */
	{VIN2A_D0, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE14)},	/* vin2a_d0.vin2a_d0 */
	{VIN2A_D1, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE14)},	/* vin2a_d1.vin2a_d1 */
	{VIN2A_D2, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE14)},	/* vin2a_d2.vin2a_d2 */
	{VIN2A_D3, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE8)},	/* vin2a_d3.vin2a_d3 */
	{VIN2A_D4, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE8)},	/* vin2a_d4.vin2a_d4 */
	{VIN2A_D5, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE8)},	/* vin2a_d5.vin2a_d5 */
	{VIN2A_D6, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE6)},	/* vin2a_d6.vin2a_d6 */
	{VIN2A_D7, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE6)},	/* vin2a_d7.vin2a_d7 */
	{VIN2A_D8, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE2)},	/* vin2a_d8.vin2a_d8 */
	{VIN2A_D9, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE2)},	/* vin2a_d9.vin2a_d9 */
	{VIN2A_D10, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE5)},	/* vin2a_d10.vin2a_d10 */
	{VIN2A_D11, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE5)},	/* vin2a_d11.vin2a_d11 */
	{VIN2A_D12, (M3 | PIN_OUTPUT | MANUAL_MODE)},	/* vin2a_d12.rgmii1_txc */
	{VIN2A_D13, (M3 | PIN_OUTPUT | MANUAL_MODE)},	/* vin2a_d13.rgmii1_txctl */
	{VIN2A_D14, (M3 | PIN_OUTPUT | MANUAL_MODE)},	/* vin2a_d14.rgmii1_txd3 */
	{VIN2A_D15, (M3 | PIN_OUTPUT | MANUAL_MODE)},	/* vin2a_d15.rgmii1_txd2 */
	{VIN2A_D16, (M3 | PIN_OUTPUT | MANUAL_MODE)},	/* vin2a_d16.rgmii1_txd1 */
	{VIN2A_D17, (M3 | PIN_OUTPUT | MANUAL_MODE)},	/* vin2a_d17.rgmii1_txd0 */
	{VIN2A_D18, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d18.rgmii1_rxc */
	{VIN2A_D19, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d19.rgmii1_rxctl */
	{VIN2A_D20, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d20.rgmii1_rxd3 */
	{VIN2A_D21, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d21.rgmii1_rxd2 */
	{VIN2A_D22, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d22.rgmii1_rxd1 */
	{VIN2A_D23, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d23.rgmii1_rxd0 */
	{VOUT1_D2, (M0 | PIN_INPUT_PULLDOWN)},	/* N/A.N/A */
	{VOUT1_D10, (M0 | PIN_INPUT_PULLDOWN)},	/* N/A.N/A */
	{VOUT1_D18, (M0 | PIN_INPUT_PULLDOWN)},	/* N/A.N/A */
	{MDIO_MCLK, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* mdio_mclk.mdio_mclk */
	{MDIO_D, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* mdio_d.mdio_d */
	{RGMII0_TXC, (M0 | PIN_OUTPUT | MANUAL_MODE)},	/* rgmii0_txc.rgmii0_txc */
	{RGMII0_TXCTL, (M0 | PIN_OUTPUT | MANUAL_MODE)},	/* rgmii0_txctl.rgmii0_txctl */
	{RGMII0_TXD3, (M0 | PIN_OUTPUT | MANUAL_MODE)},	/* rgmii0_txd3.rgmii0_txd3 */
	{RGMII0_TXD2, (M0 | PIN_OUTPUT | MANUAL_MODE)},	/* rgmii0_txd2.rgmii0_txd2 */
	{RGMII0_TXD1, (M0 | PIN_OUTPUT | MANUAL_MODE)},	/* rgmii0_txd1.rgmii0_txd1 */
	{RGMII0_TXD0, (M0 | PIN_OUTPUT | MANUAL_MODE)},	/* rgmii0_txd0.rgmii0_txd0 */
	{RGMII0_RXC, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_rxc.rgmii0_rxc */
	{RGMII0_RXCTL, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_rxctl.rgmii0_rxctl */
	{RGMII0_RXD3, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_rxd3.rgmii0_rxd3 */
	{RGMII0_RXD2, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_rxd2.rgmii0_rxd2 */
	{RGMII0_RXD1, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_rxd1.rgmii0_rxd1 */
	{RGMII0_RXD0, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_rxd0.rgmii0_rxd0 */
	{USB1_DRVVBUS, (M0 | PIN_INPUT_SLEW)},	/* usb1_drvvbus.usb1_drvvbus */
	{USB2_DRVVBUS, (M0 | PIN_INPUT_SLEW)},	/* usb2_drvvbus.usb2_drvvbus */
	{GPIO6_14, (M9 | PIN_INPUT_PULLUP)},	/* gpio6_14.i2c3_sda */
	{GPIO6_15, (M9 | PIN_INPUT_PULLUP)},	/* gpio6_15.i2c3_scl */
	{GPIO6_16, (M14 | PIN_INPUT_PULLUP)},	/* gpio6_16.gpio6_16 */
	{XREF_CLK2, (M5 | PIN_INPUT_PULLDOWN)},	/* xref_clk2.atl_clk2 */
	{MCASP1_ACLKX, (M14 | PIN_INPUT)},	/* mcasp1_aclkx.gpio7_31 */
	{MCASP1_FSX, (M14 | 0x000d0000)},	/* mcasp1_fsx.gpio7_30 */
	{MCASP1_AXR0, (M10 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* mcasp1_axr0.i2c5_sda */
	{MCASP1_AXR1, (M10 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* mcasp1_axr1.i2c5_scl */
	{MCASP1_AXR2, (M14 | PIN_INPUT_PULLDOWN)},	/* mcasp1_axr2.gpio5_4 */
	{MCASP1_AXR3, (M14 | PIN_INPUT_PULLDOWN)},	/* mcasp1_axr3.gpio5_5 */
	{MCASP1_AXR4, (M14 | PIN_INPUT_PULLDOWN)},	/* mcasp1_axr4.gpio5_6 */
	{MCASP1_AXR5, (M14 | PIN_INPUT_PULLDOWN)},	/* mcasp1_axr5.gpio5_7 */
	{MCASP1_AXR6, (M14 | PIN_INPUT_PULLDOWN)},	/* mcasp1_axr6.gpio5_8 */
	{MCASP1_AXR7, (M14 | PIN_INPUT_PULLDOWN)},	/* mcasp1_axr7.gpio5_9 */
	{MCASP1_AXR12, (M1 | PIN_INPUT_SLEW | VIRTUAL_MODE10)},	/* mcasp1_axr12.mcasp7_axr0 */
	{MCASP1_AXR13, (M1 | PIN_INPUT_SLEW)},	/* mcasp1_axr13.mcasp7_axr1 */
	{MCASP1_AXR14, (M1 | PIN_INPUT_SLEW | VIRTUAL_MODE10)},	/* mcasp1_axr14.mcasp7_aclkx */
	{MCASP1_AXR15, (M1 | PIN_INPUT_SLEW | VIRTUAL_MODE10)},	/* mcasp1_axr15.mcasp7_fsx */
	{MCASP3_ACLKX, (M0 | PIN_INPUT_PULLDOWN)},	/* mcasp3_aclkx.mcasp3_aclkx */
	{MCASP3_FSX, (M0 | PIN_INPUT_SLEW)},	/* mcasp3_fsx.mcasp3_fsx */
	{MCASP3_AXR0, (M0 | PIN_INPUT_SLEW)},	/* mcasp3_axr0.mcasp3_axr0 */
	{MCASP3_AXR1, (M0 | PIN_INPUT_SLEW | VIRTUAL_MODE6)},	/* mcasp3_axr1.mcasp3_axr1 */
	{MMC1_CLK, (M0 | PIN_INPUT_PULLUP)},	/* mmc1_clk.mmc1_clk */
	{MMC1_CMD, (M0 | PIN_INPUT_PULLUP)},	/* mmc1_cmd.mmc1_cmd */
	{MMC1_DAT0, (M0 | PIN_INPUT_PULLUP)},	/* mmc1_dat0.mmc1_dat0 */
	{MMC1_DAT1, (M0 | PIN_INPUT_PULLUP)},	/* mmc1_dat1.mmc1_dat1 */
	{MMC1_DAT2, (M0 | PIN_INPUT_PULLUP)},	/* mmc1_dat2.mmc1_dat2 */
	{MMC1_DAT3, (M0 | PIN_INPUT_PULLUP)},	/* mmc1_dat3.mmc1_dat3 */
	{MMC1_SDCD, (M14 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* mmc1_sdcd.gpio6_27 */
	{MMC1_SDWP, (M14 | PIN_INPUT_SLEW)},	/* mmc1_sdwp.gpio6_28 */
	{SPI1_SCLK, (M0 | PIN_INPUT_PULLDOWN)},	/* spi1_sclk.spi1_sclk */
	{SPI1_D1, (M0 | PIN_INPUT_PULLDOWN)},	/* spi1_d1.spi1_d1 */
	{SPI1_D0, (M0 | PIN_INPUT_PULLDOWN)},	/* spi1_d0.spi1_d0 */
	{SPI1_CS0, (M0 | PIN_INPUT_PULLUP)},	/* spi1_cs0.spi1_cs0 */
	{SPI1_CS1, (M14 | PIN_INPUT_PULLUP)},	/* spi1_cs1.gpio7_11 */
	{SPI1_CS2, (M14 | PIN_INPUT_PULLDOWN)},	/* spi1_cs2.gpio7_12 */
	{SPI1_CS3, (M6 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* spi1_cs3.hdmi1_cec */
	{SPI2_SCLK, (M1 | PIN_INPUT_PULLDOWN)},	/* spi2_sclk.uart3_rxd */
	{SPI2_D1, (M1 | PIN_INPUT_SLEW)},	/* spi2_d1.uart3_txd */
	{SPI2_D0, (M1 | PIN_INPUT_SLEW)},	/* spi2_d0.uart3_ctsn */
	{SPI2_CS0, (M1 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* spi2_cs0.uart3_rtsn */
	{DCAN1_TX, (M15 | PULL_UP)},	/* dcan1_tx.safe for dcan1_tx */
	{DCAN1_RX, (M14 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* dcan1_rx.gpio1_15 */
	{UART1_RXD, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* uart1_rxd.uart1_rxd */
	{UART1_TXD, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* uart1_txd.uart1_txd */
	{UART1_CTSN, (M3 | PIN_INPUT_PULLUP)},	/* uart1_ctsn.mmc4_clk */
	{UART1_RTSN, (M3 | PIN_INPUT_PULLUP)},	/* uart1_rtsn.mmc4_cmd */
	{UART2_RXD, (M3 | PIN_INPUT_PULLUP)},	/* uart2_rxd.mmc4_dat0 */
	{UART2_TXD, (M3 | PIN_INPUT_PULLUP)},	/* uart2_txd.mmc4_dat1 */
	{UART2_CTSN, (M3 | PIN_INPUT_PULLUP)},	/* uart2_ctsn.mmc4_dat2 */
	{UART2_RTSN, (M3 | PIN_INPUT_PULLUP)},	/* uart2_rtsn.mmc4_dat3 */
	{I2C2_SDA, (M1 | PIN_INPUT_PULLUP)},	/* i2c2_sda.hdmi1_ddc_scl */
	{I2C2_SCL, (M1 | PIN_INPUT_PULLUP)},	/* i2c2_scl.hdmi1_ddc_sda */
	{WAKEUP0, (M15 | PULL_UP)},	/* Wakeup0.safe for dcan1_rx */
	{WAKEUP3, (M1 | PULL_ENA | PULL_UP)},	/* Wakeup3.sys_nirq1 */
};

const struct pad_conf_entry early_padconf[] = {
#if (CONFIG_CONS_INDEX == 1)
	{UART1_RXD, (PIN_INPUT_SLEW | M0)}, /* UART1_RXD */
	{UART1_TXD, (PIN_INPUT_SLEW | M0)}, /* UART1_TXD */
#endif
	{I2C1_SDA, (PIN_INPUT | M0)},	/* I2C1_SDA */
	{I2C1_SCL, (PIN_INPUT | M0)},	/* I2C1_SCL */
};

#ifdef CONFIG_IODELAY_RECALIBRATION
const struct iodelay_cfg_entry iodelay_cfg_array[] = {
	{0x6F0, 359, 0}, /* RGMMI0_RXC_IN */
	{0x6FC, 129, 1896}, /* RGMMI0_RXCTL_IN */
	{0x708, 80, 1391}, /* RGMMI0_RXD0_IN */
	{0x714, 196, 1522}, /* RGMMI0_RXD1_IN */
	{0x720, 40, 1860}, /* RGMMI0_RXD2_IN */
	{0x72C, 0, 1956}, /* RGMMI0_RXD3_IN */
	{0x740, 0, 220}, /* RGMMI0_TXC_OUT */
	{0x74C, 1820, 180}, /* RGMMI0_TXCTL_OUT */
	{0x758, 1740, 440}, /* RGMMI0_TXD0_OUT */
	{0x764, 1740, 240}, /* RGMMI0_TXD1_OUT */
	{0x770, 1680, 380}, /* RGMMI0_TXD2_OUT */
	{0x77C, 1740, 440}, /* RGMMI0_TXD3_OUT */
};
#endif

#ifdef CONFIG_OMAP_MMC1_HS_52
#define DRA74x_MMC1_PAD_CONF \
	{ MMC1_CLK, (M0 | PIN_INPUT_PULLUP | VIRTUAL_MODE11) },	/* mmc1_clk.mmc1_clk */	\
	{ MMC1_CMD, (M0 | PIN_INPUT_PULLUP | VIRTUAL_MODE11) },	/* mmc1_cmd.mmc1_cmd */	\
	{ MMC1_DAT0, (M0 | PIN_INPUT_PULLUP | VIRTUAL_MODE11) },	/* mmc1_dat0.mmc1_dat0 */	\
	{ MMC1_DAT1, (M0 | PIN_INPUT_PULLUP | VIRTUAL_MODE11) },	/* mmc1_dat1.mmc1_dat1 */	\
	{ MMC1_DAT2, (M0 | PIN_INPUT_PULLUP | VIRTUAL_MODE11) },	/* mmc1_dat2.mmc1_dat2 */	\
	{ MMC1_DAT3, (M0 | PIN_INPUT_PULLUP | VIRTUAL_MODE11) },	/* mmc1_dat3.mmc1_dat3 */	\

#define DRA72x_MMC1_PAD_CONF \
	{ MMC1_CLK, (M0 | PIN_INPUT_PULLUP) },	/* mmc1_clk.mmc1_clk */ \
	{ MMC1_CMD, (M0 | PIN_INPUT_PULLUP) },	/* mmc1_cmd.mmc1_cmd */ \
	{ MMC1_DAT0, (M0 | PIN_INPUT_PULLUP) },	/* mmc1_dat0.mmc1_dat0 */ \
	{ MMC1_DAT1, (M0 | PIN_INPUT_PULLUP) },	/* mmc1_dat1.mmc1_dat1 */ \
	{ MMC1_DAT2, (M0 | PIN_INPUT_PULLUP) },	/* mmc1_dat2.mmc1_dat2 */ \
	{ MMC1_DAT3, (M0 | PIN_INPUT_PULLUP) },	/* mmc1_dat3.mmc1_dat3 */ \

#else
#define DRA74x_MMC1_PAD_CONF \
	{MMC1_CLK, (M0 | PIN_INPUT_PULLUP)},	/* mmc1_clk.mmc1_clk */	\
	{MMC1_CMD, (M0 | PIN_INPUT_PULLUP)},	/* mmc1_cmd.mmc1_cmd */	\
	{MMC1_DAT0, (M0 | PIN_INPUT_PULLUP)},	/* mmc1_dat0.mmc1_dat0 */	\
	{MMC1_DAT1, (M0 | PIN_INPUT_PULLUP)},	/* mmc1_dat1.mmc1_dat1 */	\
	{MMC1_DAT2, (M0 | PIN_INPUT_PULLUP)},	/* mmc1_dat2.mmc1_dat2 */	\
	{MMC1_DAT3, (M0 | PIN_INPUT_PULLUP)},	/* mmc1_dat3.mmc1_dat3 */	\

#define DRA72x_MMC1_PAD_CONF \
	{ MMC1_CLK, (M0 | PIN_INPUT_PULLUP) },	/* mmc1_clk.mmc1_clk */ \
	{ MMC1_CMD, (M0 | PIN_INPUT_PULLUP) },	/* mmc1_cmd.mmc1_cmd */ \
	{ MMC1_DAT0, (M0 | PIN_INPUT_PULLUP) },	/* mmc1_dat0.mmc1_dat0 */ \
	{ MMC1_DAT1, (M0 | PIN_INPUT_PULLUP) },	/* mmc1_dat1.mmc1_dat1 */ \
	{ MMC1_DAT2, (M0 | PIN_INPUT_PULLUP) },	/* mmc1_dat2.mmc1_dat2 */ \
	{ MMC1_DAT3, (M0 | PIN_INPUT_PULLUP) },	/* mmc1_dat3.mmc1_dat3 */ \

#endif /* CONFIG_OMAP_MMC1_HS_52 */

#ifdef CONFIG_OMAP_MMC2_DDR_52
#define DRA74x_MMC2_PAD_CONF \
	{ GPMC_A19, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a19.mmc2_dat4 */ \
	{ GPMC_A20, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a20.mmc2_dat5 */ \
	{ GPMC_A21, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a21.mmc2_dat6 */ \
	{ GPMC_A22, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a22.mmc2_dat7 */ \
	{ GPMC_A23, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a23.mmc2_clk */ \
	{ GPMC_A24, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a24.mmc2_dat0 */ \
	{ GPMC_A25, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a25.mmc2_dat1 */ \
	{ GPMC_A26, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a26.mmc2_dat2 */ \
	{ GPMC_A27, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a27.mmc2_dat3 */ \
	{ GPMC_CS1, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_cs1.mmc2_cmd */ \

#define DRA74x_MMC2_DELAY_CONF_ES11 \
	{ 0x018C,     0,     0 },	/* CFG_GPMC_A19_IN : MMC2_DAT4 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x0190,     0,     0 },	/* CFG_GPMC_A19_OEN : MMC2_DAT4 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x0194,   174,     0 },	/* CFG_GPMC_A19_OUT : MMC2_DAT4 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01A4,   274,   240 },	/* CFG_GPMC_A20_IN : MMC2_DAT5 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01A8,     0,     0 },	/* CFG_GPMC_A20_OEN : MMC2_DAT5 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01AC,   168,     0 },	/* CFG_GPMC_A20_OUT : MMC2_DAT5 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01B0,     0,    60 },	/* CFG_GPMC_A21_IN : MMC2_DAT6 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01B4,     0,     0 },	/* CFG_GPMC_A21_OEN : MMC2_DAT6 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01B8,   136,     0 },	/* CFG_GPMC_A21_OUT : MMC2_DAT6 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01BC,     0,    60 },	/* CFG_GPMC_A22_IN : MMC2_DAT7 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01C0,     0,     0 },	/* CFG_GPMC_A22_OEN : MMC2_DAT7 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01C4,     0,     0 },	/* CFG_GPMC_A22_OUT : MMC2_DAT7 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01C8,   514,   360 },	/* CFG_GPMC_A23_IN : MMC2_CLK - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01D0,   879,     0 },	/* CFG_GPMC_A23_OUT : MMC2_CLK - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01D4,   187,   120 },	/* CFG_GPMC_A24_IN : MMC2_DAT0 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01D8,     0,     0 },	/* CFG_GPMC_A24_OEN : MMC2_DAT0 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01DC,     0,     0 },	/* CFG_GPMC_A24_OUT : MMC2_DAT0 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01E0,     0,     0 },	/* CFG_GPMC_A25_IN : MMC2_DAT1 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01E4,     0,     0 },	/* CFG_GPMC_A25_OEN : MMC2_DAT1 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01E8,    34,     0 },	/* CFG_GPMC_A25_OUT : MMC2_DAT1 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01EC,     0,    60 },	/* CFG_GPMC_A26_IN : MMC2_DAT2 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01F0,     0,     0 },	/* CFG_GPMC_A26_OEN : MMC2_DAT2 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01F4,   120,     0 },	/* CFG_GPMC_A26_OUT : MMC2_DAT2 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01F8,   121,    60 },	/* CFG_GPMC_A27_IN : MMC2_DAT3 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x01FC,     0,     0 },	/* CFG_GPMC_A27_OEN : MMC2_DAT3 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x0200,     0,     0 },	/* CFG_GPMC_A27_OUT : MMC2_DAT3 - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x0360,     0,     0 },	/* CFG_GPMC_CS1_IN : MMC2_CMD - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x0364,     0,     0 },	/* CFG_GPMC_CS1_OEN : MMC2_CMD - MMC2_DDR_1V8_MANUAL1 */ \
	{ 0x0368,    11,     0 },	/* CFG_GPMC_CS1_OUT : MMC2_CMD - MMC2_DDR_1V8_MANUAL1 */ \

#define DRA74x_MMC2_DELAY_CONF_ES20 \
	{ 0x018C,   270,     0 },	/* CFG_GPMC_A19_IN : MMC2_DAT4 - MMC2_DDR_MANUAL1 */ \
	{ 0x0190,     0,     0 },	/* CFG_GPMC_A19_OEN : MMC2_DAT4 - MMC2_DDR_MANUAL1 */ \
	{ 0x0194,   170,     0 },	/* CFG_GPMC_A19_OUT : MMC2_DAT4 - MMC2_DDR_MANUAL1 */ \
	{ 0x01A4,   758,     0 },	/* CFG_GPMC_A20_IN : MMC2_DAT5 - MMC2_DDR_MANUAL1 */ \
	{ 0x01A8,     0,     0 },	/* CFG_GPMC_A20_OEN : MMC2_DAT5 - MMC2_DDR_MANUAL1 */ \
	{ 0x01AC,    81,     0 },	/* CFG_GPMC_A20_OUT : MMC2_DAT5 - MMC2_DDR_MANUAL1 */ \
	{ 0x01B0,   286,     0 },	/* CFG_GPMC_A21_IN : MMC2_DAT6 - MMC2_DDR_MANUAL1 */ \
	{ 0x01B4,     0,     0 },	/* CFG_GPMC_A21_OEN : MMC2_DAT6 - MMC2_DDR_MANUAL1 */ \
	{ 0x01B8,   123,     0 },	/* CFG_GPMC_A21_OUT : MMC2_DAT6 - MMC2_DDR_MANUAL1 */ \
	{ 0x01BC,   346,     0 },	/* CFG_GPMC_A22_IN : MMC2_DAT7 - MMC2_DDR_MANUAL1 */ \
	{ 0x01C0,     0,     0 },	/* CFG_GPMC_A22_OEN : MMC2_DAT7 - MMC2_DDR_MANUAL1 */ \
	{ 0x01C4,    55,     0 },	/* CFG_GPMC_A22_OUT : MMC2_DAT7 - MMC2_DDR_MANUAL1 */ \
	{ 0x01C8,     0,     0 },	/* CFG_GPMC_A23_IN : MMC2_CLK - MMC2_DDR_MANUAL1 */ \
	{ 0x01D0,   422,     0 },	/* CFG_GPMC_A23_OUT : MMC2_CLK - MMC2_DDR_MANUAL1 */ \
	{ 0x01D4,   642,     0 },	/* CFG_GPMC_A24_IN : MMC2_DAT0 - MMC2_DDR_MANUAL1 */ \
	{ 0x01D8,     0,     0 },	/* CFG_GPMC_A24_OEN : MMC2_DAT0 - MMC2_DDR_MANUAL1 */ \
	{ 0x01DC,     0,     0 },	/* CFG_GPMC_A24_OUT : MMC2_DAT0 - MMC2_DDR_MANUAL1 */ \
	{ 0x01E0,   128,     0 },	/* CFG_GPMC_A25_IN : MMC2_DAT1 - MMC2_DDR_MANUAL1 */ \
	{ 0x01E4,     0,     0 },	/* CFG_GPMC_A25_OEN : MMC2_DAT1 - MMC2_DDR_MANUAL1 */ \
	{ 0x01E8,     0,     0 },	/* CFG_GPMC_A25_OUT : MMC2_DAT1 - MMC2_DDR_MANUAL1 */ \
	{ 0x01EC,   395,     0 },	/* CFG_GPMC_A26_IN : MMC2_DAT2 - MMC2_DDR_MANUAL1 */ \
	{ 0x01F0,     0,     0 },	/* CFG_GPMC_A26_OEN : MMC2_DAT2 - MMC2_DDR_MANUAL1 */ \
	{ 0x01F4,     0,     0 },	/* CFG_GPMC_A26_OUT : MMC2_DAT2 - MMC2_DDR_MANUAL1 */ \
	{ 0x01F8,   623,     0 },	/* CFG_GPMC_A27_IN : MMC2_DAT3 - MMC2_DDR_MANUAL1 */ \
	{ 0x01FC,     0,     0 },	/* CFG_GPMC_A27_OEN : MMC2_DAT3 - MMC2_DDR_MANUAL1 */ \
	{ 0x0200,    54,     0 },	/* CFG_GPMC_A27_OUT : MMC2_DAT3 - MMC2_DDR_MANUAL1 */ \
	{ 0x0360,     0,     0 },	/* CFG_GPMC_CS1_IN : MMC2_CMD - MMC2_DDR_MANUAL1 */ \
	{ 0x0364,     0,     0 },	/* CFG_GPMC_CS1_OEN : MMC2_CMD - MMC2_DDR_MANUAL1 */ \
	{ 0x0368,     0,     0 },	/* CFG_GPMC_CS1_OUT : MMC2_CMD - MMC2_DDR_MANUAL1 */ \

#define DRA72x_MMC2_PAD_CONF \
	{ GPMC_A19, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a19.mmc2_dat4 */ \
	{ GPMC_A20, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a20.mmc2_dat5 */ \
	{ GPMC_A21, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a21.mmc2_dat6 */ \
	{ GPMC_A22, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a22.mmc2_dat7 */ \
	{ GPMC_A23, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a23.mmc2_clk */ \
	{ GPMC_A24, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a24.mmc2_dat0 */ \
	{ GPMC_A25, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a25.mmc2_dat1 */ \
	{ GPMC_A26, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a26.mmc2_dat2 */ \
	{ GPMC_A27, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_a27.mmc2_dat3 */ \
	{ GPMC_CS1, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_cs1.mmc2_cmd */ \

#define DRA72x_MMC2_DELAY_CONF_ES10 \
	{ 0x018C,     0,     0 },	/* CFG_GPMC_A19_IN : MMC2_DAT4 - MMC2_MANUAL1 */ \
	{ 0x0190,     0,     0 },	/* CFG_GPMC_A19_OEN : MMC2_DAT4 - MMC2_MANUAL1 */ \
	{ 0x0194,   100,     0 },	/* CFG_GPMC_A19_OUT : MMC2_DAT4 - MMC2_MANUAL1 */ \
	{ 0x01A4,   391,     0 },	/* CFG_GPMC_A20_IN : MMC2_DAT5 - MMC2_MANUAL1 */ \
	{ 0x01A8,     0,     0 },	/* CFG_GPMC_A20_OEN : MMC2_DAT5 - MMC2_MANUAL1 */ \
	{ 0x01AC,   219,     0 },	/* CFG_GPMC_A20_OUT : MMC2_DAT5 - MMC2_MANUAL1 */ \
	{ 0x01B0,     0,     0 },	/* CFG_GPMC_A21_IN : MMC2_DAT6 - MMC2_MANUAL1 */ \
	{ 0x01B4,     0,     0 },	/* CFG_GPMC_A21_OEN : MMC2_DAT6 - MMC2_MANUAL1 */ \
	{ 0x01B8,    24,     0 },	/* CFG_GPMC_A21_OUT : MMC2_DAT6 - MMC2_MANUAL1 */ \
	{ 0x01BC,   211,     0 },	/* CFG_GPMC_A22_IN : MMC2_DAT7 - MMC2_MANUAL1 */ \
	{ 0x01C0,     0,     0 },	/* CFG_GPMC_A22_OEN : MMC2_DAT7 - MMC2_MANUAL1 */ \
	{ 0x01C4,    88,     0 },	/* CFG_GPMC_A22_OUT : MMC2_DAT7 - MMC2_MANUAL1 */ \
	{ 0x01C8,     0,     0 },	/* CFG_GPMC_A23_IN : MMC2_CLK - MMC2_MANUAL1 */ \
	{ 0x01D0,   626,     0 },	/* CFG_GPMC_A23_OUT : MMC2_CLK - MMC2_MANUAL1 */ \
	{ 0x01D4,   320,     0 },	/* CFG_GPMC_A24_IN : MMC2_DAT0 - MMC2_MANUAL1 */ \
	{ 0x01D8,     0,     0 },	/* CFG_GPMC_A24_OEN : MMC2_DAT0 - MMC2_MANUAL1 */ \
	{ 0x01DC,     0,     0 },	/* CFG_GPMC_A24_OUT : MMC2_DAT0 - MMC2_MANUAL1 */ \
	{ 0x01E0,     0,     0 },	/* CFG_GPMC_A25_IN : MMC2_DAT1 - MMC2_MANUAL1 */ \
	{ 0x01E4,     0,     0 },	/* CFG_GPMC_A25_OEN : MMC2_DAT1 - MMC2_MANUAL1 */ \
	{ 0x01E8,   172,     0 },	/* CFG_GPMC_A25_OUT : MMC2_DAT1 - MMC2_MANUAL1 */ \
	{ 0x01EC,   159,     0 },	/* CFG_GPMC_A26_IN : MMC2_DAT2 - MMC2_MANUAL1 */ \
	{ 0x01F0,     0,     0 },	/* CFG_GPMC_A26_OEN : MMC2_DAT2 - MMC2_MANUAL1 */ \
	{ 0x01F4,   177,     0 },	/* CFG_GPMC_A26_OUT : MMC2_DAT2 - MMC2_MANUAL1 */ \
	{ 0x01F8,   232,     0 },	/* CFG_GPMC_A27_IN : MMC2_DAT3 - MMC2_MANUAL1 */ \
	{ 0x01FC,     0,     0 },	/* CFG_GPMC_A27_OEN : MMC2_DAT3 - MMC2_MANUAL1 */ \
	{ 0x0200,     0,     0 },	/* CFG_GPMC_A27_OUT : MMC2_DAT3 - MMC2_MANUAL1 */ \
	{ 0x0360,     0,     0 },	/* CFG_GPMC_CS1_IN : MMC2_CMD - MMC2_MANUAL1 */ \
	{ 0x0364,     0,     0 },	/* CFG_GPMC_CS1_OEN : MMC2_CMD - MMC2_MANUAL1 */ \
	{ 0x0368,     0,     0 },	/* CFG_GPMC_CS1_OUT : MMC2_CMD - MMC2_MANUAL1 */ \

#else
#define DRA74x_MMC2_PAD_CONF \
	{GPMC_A19, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a19.mmc2_dat4 */ \
	{GPMC_A20, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a20.mmc2_dat5 */ \
	{GPMC_A21, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a21.mmc2_dat6 */ \
	{GPMC_A22, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a22.mmc2_dat7 */ \
	{GPMC_A23, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a23.mmc2_clk */ \
	{GPMC_A24, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a24.mmc2_dat0 */ \
	{GPMC_A25, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a25.mmc2_dat1 */ \
	{GPMC_A26, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a26.mmc2_dat2 */ \
	{GPMC_A27, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a27.mmc2_dat3 */ \
	{GPMC_CS1, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_cs1.mmc2_cmd */ \

#define DRA74x_MMC2_DELAY_CONF_ES11	/* No delay for default */
#define DRA74x_MMC2_DELAY_CONF_ES20	/* No delay for default */

#define DRA72x_MMC2_PAD_CONF \
	{ GPMC_A19, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a19.mmc2_dat4 */ \
	{ GPMC_A20, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a20.mmc2_dat5 */ \
	{ GPMC_A21, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a21.mmc2_dat6 */ \
	{ GPMC_A22, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a22.mmc2_dat7 */ \
	{ GPMC_A23, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a23.mmc2_clk */ \
	{ GPMC_A24, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a24.mmc2_dat0 */ \
	{ GPMC_A25, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a25.mmc2_dat1 */ \
	{ GPMC_A26, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a26.mmc2_dat2 */ \
	{ GPMC_A27, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a27.mmc2_dat3 */ \
	{ GPMC_CS1, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_cs1.mmc2_cmd */ \

#define DRA72x_MMC2_DELAY_CONF_ES10	/* No delay for default */
#endif /* CONFIG_OMAP_MMC2_DDR_52 */

const struct pad_conf_entry dra74x_core_padconf_array[] = {
	{GPMC_AD0, (M3 | PIN_INPUT)},	/* gpmc_ad0.vout3_d0 */
	{GPMC_AD1, (M3 | PIN_INPUT)},	/* gpmc_ad1.vout3_d1 */
	{GPMC_AD2, (M3 | PIN_INPUT)},	/* gpmc_ad2.vout3_d2 */
	{GPMC_AD3, (M3 | PIN_INPUT)},	/* gpmc_ad3.vout3_d3 */
	{GPMC_AD4, (M3 | PIN_INPUT)},	/* gpmc_ad4.vout3_d4 */
	{GPMC_AD5, (M3 | PIN_INPUT)},	/* gpmc_ad5.vout3_d5 */
	{GPMC_AD6, (M3 | PIN_INPUT)},	/* gpmc_ad6.vout3_d6 */
	{GPMC_AD7, (M3 | PIN_INPUT)},	/* gpmc_ad7.vout3_d7 */
	{GPMC_AD8, (M3 | PIN_INPUT)},	/* gpmc_ad8.vout3_d8 */
	{GPMC_AD9, (M3 | PIN_INPUT)},	/* gpmc_ad9.vout3_d9 */
	{GPMC_AD10, (M3 | PIN_INPUT)},	/* gpmc_ad10.vout3_d10 */
	{GPMC_AD11, (M3 | PIN_INPUT)},	/* gpmc_ad11.vout3_d11 */
	{GPMC_AD12, (M3 | PIN_INPUT)},	/* gpmc_ad12.vout3_d12 */
	{GPMC_AD13, (M3 | PIN_INPUT)},	/* gpmc_ad13.vout3_d13 */
	{GPMC_AD14, (M3 | PIN_INPUT)},	/* gpmc_ad14.vout3_d14 */
	{GPMC_AD15, (M3 | PIN_INPUT)},	/* gpmc_ad15.vout3_d15 */
	{GPMC_A0, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a0.vout3_d16 */
	{GPMC_A1, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a1.vout3_d17 */
	{GPMC_A2, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a2.vout3_d18 */
	{GPMC_A3, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a3.vout3_d19 */
	{GPMC_A4, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a4.vout3_d20 */
	{GPMC_A5, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a5.vout3_d21 */
	{GPMC_A6, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a6.vout3_d22 */
	{GPMC_A7, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a7.vout3_d23 */
	{GPMC_A8, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a8.vout3_hsync */
	{GPMC_A9, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a9.vout3_vsync */
	{GPMC_A10, (M3 | PIN_INPUT_PULLDOWN)},	/* gpmc_a10.vout3_de */
	{GPMC_A11, (M14 | PIN_INPUT_PULLDOWN)},	/* gpmc_a11.gpio2_1 */
	{GPMC_A13, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* gpmc_a13.qspi1_rtclk */
	{GPMC_A14, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* gpmc_a14.qspi1_d3 */
	{GPMC_A15, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* gpmc_a15.qspi1_d2 */
	{GPMC_A16, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* gpmc_a16.qspi1_d0 */
	{GPMC_A17, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* gpmc_a17.qspi1_d1 */
	{GPMC_A18, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* gpmc_a18.qspi1_sclk */
	{GPMC_A19, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a19.mmc2_dat4 */
	{GPMC_A20, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a20.mmc2_dat5 */
	{GPMC_A21, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a21.mmc2_dat6 */
	{GPMC_A22, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a22.mmc2_dat7 */
	{GPMC_A23, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a23.mmc2_clk */
	{GPMC_A24, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a24.mmc2_dat0 */
	{GPMC_A25, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a25.mmc2_dat1 */
	{GPMC_A26, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a26.mmc2_dat2 */
	{GPMC_A27, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_a27.mmc2_dat3 */
	{GPMC_CS1, (M1 | PIN_INPUT_PULLUP)},	/* gpmc_cs1.mmc2_cmd */
	{GPMC_CS2, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE)},	/* gpmc_cs2.qspi1_cs0 */
	{GPMC_CS3, (M3 | PIN_INPUT_PULLUP)},	/* gpmc_cs3.vout3_clk */
	{VIN1A_CLK0, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_clk0.vin1a_clk0 */
	{VIN1A_DE0, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_de0.vin1a_de0 */
	{VIN1A_FLD0, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_fld0.vin1a_fld0 */
	{VIN1A_HSYNC0, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_hsync0.vin1a_hsync0 */
	{VIN1A_VSYNC0, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_vsync0.vin1a_vsync0 */
	{VIN1A_D0, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d0.vin1a_d0 */
	{VIN1A_D1, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d1.vin1a_d1 */
	{VIN1A_D2, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d2.vin1a_d2 */
	{VIN1A_D3, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d3.vin1a_d3 */
	{VIN1A_D4, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d4.vin1a_d4 */
	{VIN1A_D5, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d5.vin1a_d5 */
	{VIN1A_D6, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d6.vin1a_d6 */
	{VIN1A_D7, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d7.vin1a_d7 */
	{VIN1A_D8, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d8.vin1a_d8 */
	{VIN1A_D9, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d9.vin1a_d9 */
	{VIN1A_D10, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d10.vin1a_d10 */
	{VIN1A_D11, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d11.vin1a_d11 */
	{VIN1A_D12, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d12.vin1a_d12 */
	{VIN1A_D13, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d13.vin1a_d13 */
	{VIN1A_D14, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d14.vin1a_d14 */
	{VIN1A_D15, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d15.vin1a_d15 */
	{VIN1A_D16, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d16.vin1a_d16 */
	{VIN1A_D17, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d17.vin1a_d17 */
	{VIN1A_D18, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d18.vin1a_d18 */
	{VIN1A_D19, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d19.vin1a_d19 */
	{VIN1A_D20, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d20.vin1a_d20 */
	{VIN1A_D21, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d21.vin1a_d21 */
	{VIN1A_D22, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d22.vin1a_d22 */
	{VIN1A_D23, (M0 | PIN_INPUT | MANUAL_MODE)},	/* vin1a_d23.vin1a_d23 */
	{VIN2A_D12, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d12.rgmii1_txc */
	{VIN2A_D13, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d13.rgmii1_txctl */
	{VIN2A_D14, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d14.rgmii1_txd3 */
	{VIN2A_D15, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d15.rgmii1_txd2 */
	{VIN2A_D16, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d16.rgmii1_txd1 */
	{VIN2A_D17, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d17.rgmii1_txd0 */
	{VIN2A_D18, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d18.rgmii1_rxc */
	{VIN2A_D19, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d19.rgmii1_rxctl */
	{VIN2A_D20, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d20.rgmii1_rxd3 */
	{VIN2A_D21, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d21.rgmii1_rxd2 */
	{VIN2A_D22, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d22.rgmii1_rxd1 */
	{VIN2A_D23, (M3 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* vin2a_d23.rgmii1_rxd0 */
	{VOUT1_CLK, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_clk.vout1_clk */
	{VOUT1_DE, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_de.vout1_de */
	{VOUT1_HSYNC, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_hsync.vout1_hsync */
	{VOUT1_VSYNC, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_vsync.vout1_vsync */
	{VOUT1_D0, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d0.vout1_d0 */
	{VOUT1_D1, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d1.vout1_d1 */
	{VOUT1_D2, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d2.vout1_d2 */
	{VOUT1_D3, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d3.vout1_d3 */
	{VOUT1_D4, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d4.vout1_d4 */
	{VOUT1_D5, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d5.vout1_d5 */
	{VOUT1_D6, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d6.vout1_d6 */
	{VOUT1_D7, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d7.vout1_d7 */
	{VOUT1_D8, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d8.vout1_d8 */
	{VOUT1_D9, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d9.vout1_d9 */
	{VOUT1_D10, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d10.vout1_d10 */
	{VOUT1_D11, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d11.vout1_d11 */
	{VOUT1_D12, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d12.vout1_d12 */
	{VOUT1_D13, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d13.vout1_d13 */
	{VOUT1_D14, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d14.vout1_d14 */
	{VOUT1_D15, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d15.vout1_d15 */
	{VOUT1_D16, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d16.vout1_d16 */
	{VOUT1_D17, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d17.vout1_d17 */
	{VOUT1_D18, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d18.vout1_d18 */
	{VOUT1_D19, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d19.vout1_d19 */
	{VOUT1_D20, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d20.vout1_d20 */
	{VOUT1_D21, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d21.vout1_d21 */
	{VOUT1_D22, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d22.vout1_d22 */
	{VOUT1_D23, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d23.vout1_d23 */
	{MDIO_MCLK, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* mdio_mclk.mdio_mclk */
	{MDIO_D, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* mdio_d.mdio_d */
	{RGMII0_TXC, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_txc.rgmii0_txc */
	{RGMII0_TXCTL, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_txctl.rgmii0_txctl */
	{RGMII0_TXD3, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_txd3.rgmii0_txd3 */
	{RGMII0_TXD2, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_txd2.rgmii0_txd2 */
	{RGMII0_TXD1, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_txd1.rgmii0_txd1 */
	{RGMII0_TXD0, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_txd0.rgmii0_txd0 */
	{RGMII0_RXC, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_rxc.rgmii0_rxc */
	{RGMII0_RXCTL, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_rxctl.rgmii0_rxctl */
	{RGMII0_RXD3, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_rxd3.rgmii0_rxd3 */
	{RGMII0_RXD2, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_rxd2.rgmii0_rxd2 */
	{RGMII0_RXD1, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_rxd1.rgmii0_rxd1 */
	{RGMII0_RXD0, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE)},	/* rgmii0_rxd0.rgmii0_rxd0 */
	{USB1_DRVVBUS, (M0 | PIN_INPUT_SLEW)},	/* usb1_drvvbus.usb1_drvvbus */
	{USB2_DRVVBUS, (M0 | PIN_INPUT_SLEW)},	/* usb2_drvvbus.usb2_drvvbus */
	{GPIO6_14, (M9 | PIN_INPUT_PULLUP)},	/* gpio6_14.i2c3_sda */
	{GPIO6_15, (M9 | PIN_INPUT_PULLUP)},	/* gpio6_15.i2c3_scl */
	{GPIO6_16, (M14 | PIN_INPUT_PULLUP)},	/* gpio6_16.gpio6_16 */
	{XREF_CLK2, (M5 | PIN_INPUT_PULLDOWN)},	/* xref_clk2.atl_clk2 */
	{MCASP1_ACLKX, (M0 | PIN_INPUT_PULLDOWN)},	/* mcasp1_aclkx.mcasp1_aclkx */
	{MCASP1_FSX, (M0 | PIN_INPUT_SLEW)},	/* mcasp1_fsx.mcasp1_fsx */
	{MCASP1_AXR0, (M0 | PIN_INPUT_SLEW | VIRTUAL_MODE15)},	/* mcasp1_axr0.mcasp1_axr0 */
	{MCASP1_AXR1, (M0 | PIN_INPUT_SLEW)},	/* mcasp1_axr1.mcasp1_axr1 */
	{MCASP1_AXR2, (M14 | PIN_INPUT_PULLDOWN)},	/* mcasp1_axr2.gpio5_4 */
	{MCASP1_AXR3, (M14 | PIN_INPUT_PULLDOWN)},	/* mcasp1_axr3.gpio5_5 */
	{MCASP1_AXR4, (M14 | PIN_INPUT_PULLDOWN)},	/* mcasp1_axr4.gpio5_6 */
	{MCASP1_AXR5, (M14 | PIN_INPUT_PULLDOWN)},	/* mcasp1_axr5.gpio5_7 */
	{MCASP1_AXR6, (M14 | PIN_INPUT_PULLDOWN)},	/* mcasp1_axr6.gpio5_8 */
	{MCASP1_AXR7, (M14 | PIN_INPUT_PULLDOWN)},	/* mcasp1_axr7.gpio5_9 */
	{MCASP1_AXR12, (M1 | PIN_INPUT_SLEW | VIRTUAL_MODE10)},	/* mcasp1_axr12.mcasp7_axr0 */
	{MCASP1_AXR13, (M1 | PIN_INPUT_SLEW)},	/* mcasp1_axr13.mcasp7_axr1 */
	{MCASP1_AXR14, (M1 | PIN_INPUT_SLEW | VIRTUAL_MODE10)},	/* mcasp1_axr14.mcasp7_aclkx */
	{MCASP1_AXR15, (M1 | PIN_INPUT_SLEW | VIRTUAL_MODE10)},	/* mcasp1_axr15.mcasp7_fsx */
	{MCASP2_ACLKR, (M0 | PIN_INPUT_PULLDOWN)},	/* mcasp2_aclkr.mcasp2_aclkr */
	{MCASP3_ACLKX, (M0 | PIN_INPUT_PULLDOWN)},	/* mcasp3_aclkx.mcasp3_aclkx */
	{MCASP3_FSX, (M0 | PIN_INPUT_SLEW)},	/* mcasp3_fsx.mcasp3_fsx */
	{MCASP3_AXR0, (M0 | PIN_INPUT_SLEW)},	/* mcasp3_axr0.mcasp3_axr0 */
	{MCASP3_AXR1, (M0 | PIN_INPUT_SLEW | VIRTUAL_MODE6)},	/* mcasp3_axr1.mcasp3_axr1 */
	DRA74x_MMC1_PAD_CONF
	DRA74x_MMC2_PAD_CONF
	{MMC1_SDCD, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* mmc1_sdcd.mmc1_sdcd */
	{MMC1_SDWP, (M14 | PIN_INPUT_SLEW)},	/* mmc1_sdwp.gpio6_28 */
	{GPIO6_11, (M14 | PIN_INPUT_PULLUP)},	/* gpio6_11.gpio6_11 */
	{SPI1_SCLK, (M0 | PIN_INPUT_PULLDOWN)},	/* spi1_sclk.spi1_sclk */
	{SPI1_D1, (M0 | PIN_INPUT_PULLDOWN)},	/* spi1_d1.spi1_d1 */
	{SPI1_D0, (M0 | PIN_INPUT_PULLDOWN)},	/* spi1_d0.spi1_d0 */
	{SPI1_CS0, (M0 | PIN_INPUT_PULLUP)},	/* spi1_cs0.spi1_cs0 */
	{SPI1_CS1, (M14 | PIN_OUTPUT)},		/* spi1_cs1.gpio7_11 */
	{SPI1_CS2, (M14 | PIN_INPUT_PULLDOWN)},	/* spi1_cs2.gpio7_12 */
	{SPI1_CS3, (M6 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* spi1_cs3.hdmi1_cec */
#if CONFIG_CONS_INDEX != 3
	{SPI2_SCLK, (M1 | PIN_INPUT_PULLDOWN)},	/* spi2_sclk.uart3_rxd */
	{SPI2_D1, (M1 | PIN_INPUT_SLEW)},	/* spi2_d1.uart3_txd */
#endif
	{SPI2_D0, (M1 | PIN_INPUT_SLEW)},	/* spi2_d0.uart3_ctsn */
	{SPI2_CS0, (M1 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* spi2_cs0.uart3_rtsn */
	{DCAN1_TX, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* dcan1_tx.dcan1_tx */
	{DCAN1_RX, (M14 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* dcan1_rx.gpio1_15 */
	{UART1_RXD, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* uart1_rxd.uart1_rxd */
	{UART1_TXD, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL)},	/* uart1_txd.uart1_txd */
	{UART1_CTSN, (M3 | PIN_INPUT_PULLUP)},	/* uart1_ctsn.mmc4_clk */
	{UART1_RTSN, (M3 | PIN_INPUT_PULLUP)},	/* uart1_rtsn.mmc4_cmd */
	{UART2_RXD, (M3 | PIN_INPUT_PULLUP)},	/* N/A.mmc4_dat0 */
	{UART2_TXD, (M3 | PIN_INPUT_PULLUP)},	/* uart2_txd.mmc4_dat1 */
#if CONFIG_CONS_INDEX != 3
	{UART2_CTSN, (M3 | PIN_INPUT_PULLUP)},	/* uart2_ctsn.mmc4_dat2 */
	{UART2_RTSN, (M3 | PIN_INPUT_PULLUP)},	/* uart2_rtsn.mmc4_dat3 */
#endif
	{I2C2_SDA, (M0 | PIN_INPUT_PULLUP)},	/* i2c2_sda.i2c2_sda */
	{I2C2_SCL, (M0 | PIN_INPUT_PULLUP)},	/* i2c2_scl.i2c2_scl */
	{WAKEUP0, (M1 | PIN_OUTPUT)},	/* Wakeup0.dcan1_rx */
	{WAKEUP2, (M14 | PIN_OUTPUT)},	/* Wakeup2.gpio1_2 */

#ifdef CONFIG_DRA7XX_JAMR3
	{XREF_CLK1, (M5 | PIN_INPUT_PULLDOWN)},	/* xref_clk1.atl_clk1 */
	{XREF_CLK3, (M14 | PIN_INPUT)},	/* xref_clk3.gpio6_20 */
	{MCASP1_AXR8, (M1 | PIN_OUTPUT_PULLDOWN | SLEWCONTROL)},	/* mcasp1_axr8.mcasp6_axr0 */
	{MCASP1_AXR9, (M1 | PIN_INPUT_SLEW)},	/* mcasp1_axr9.mcasp6_axr1 */
	{MCASP1_AXR10, (M1 | PIN_INPUT_SLEW)},	/* mcasp1_axr10.mcasp6_aclkx */
	{MCASP1_AXR11, (M1 | PIN_INPUT_SLEW)},	/* mcasp1_axr11.mcasp6_fsx */
	{MCASP2_ACLKX, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE9)},	/* mcasp2_aclkx.mcasp2_aclkx */
	{MCASP2_FSX, (M0 | PIN_INPUT_SLEW | VIRTUAL_MODE9)},	/* mcasp2_fsx.mcasp2_fsx */
	{MCASP2_AXR0, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE12)},	/* mcasp2_axr0.mcasp2_axr0 */
	{MCASP2_AXR1, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE12)},	/* mcasp2_axr1.mcasp2_axr1 */
	{MCASP2_AXR2, (M0 | PIN_INPUT_SLEW | VIRTUAL_MODE9)},	/* mcasp2_axr2.mcasp2_axr2 */
	{MCASP2_AXR3, (M0 | PIN_INPUT_SLEW | VIRTUAL_MODE9)},	/* mcasp2_axr3.mcasp2_axr3 */
	{MCASP2_AXR4, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE12)},	/* mcasp2_axr4.mcasp2_axr4 */
	{MCASP2_AXR5, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE12)},	/* mcasp2_axr5.mcasp2_axr5 */
	{MCASP2_AXR6, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE12)},	/* mcasp2_axr6.mcasp2_axr6 */
	{MCASP2_AXR7, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE12)},	/* mcasp2_axr7.mcasp2_axr7 */
	{MCASP4_ACLKX, (M4 | PIN_INPUT_PULLUP)},	/* mcasp4_aclkx.i2c4_sda */
	{MCASP4_FSX, (M4 | PIN_INPUT_PULLUP)},	/* mcasp4_fsx.i2c4_scl */
#endif

#ifdef CONFIG_DRA7XX_VISION
	{ VIN1B_CLK1, (M6 | PIN_INPUT | MANUAL_MODE) },	/* vin1b_clk1.vin3a_clk0 */
	{ VIN1A_D16, (M6 | PIN_INPUT | MANUAL_MODE) },	/* vin1a_d16.vin3a_d0 */
	{ VIN1A_D17, (M6 | PIN_INPUT | MANUAL_MODE) },	/* vin1a_d17.vin3a_d1 */
	{ VIN1A_D18, (M6 | PIN_INPUT | MANUAL_MODE) },	/* vin1a_d18.vin3a_d2 */
	{ VIN1A_D19, (M6 | PIN_INPUT | MANUAL_MODE) },	/* vin1a_d19.vin3a_d3 */
	{ VIN1A_D20, (M6 | PIN_INPUT | MANUAL_MODE) },	/* vin1a_d20.vin3a_d4 */
	{ VIN1A_D21, (M6 | PIN_INPUT | MANUAL_MODE) },	/* vin1a_d21.vin3a_d5 */
	{ VIN1A_D22, (M6 | PIN_INPUT | MANUAL_MODE) },	/* vin1a_d22.vin3a_d6 */
	{ VIN1A_D23, (M6 | PIN_INPUT | MANUAL_MODE) },	/* vin1a_d23.vin3a_d7 */
	{ VIN2A_CLK0, (M0 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_clk0.vin2a_clk0 */
	{ VIN2A_HSYNC0, (M0 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_hsync0.vin2a_hsync0 */
	{ VIN2A_VSYNC0, (M0 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_vsync0.vin2a_vsync0 */
	{ VIN2A_D0, (M0 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d0.vin2a_d0 */
	{ VIN2A_D1, (M0 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d1.vin2a_d1 */
	{ VIN2A_D2, (M0 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d2.vin2a_d2 */
	{ VIN2A_D3, (M0 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d3.vin2a_d3 */
	{ VIN2A_D4, (M0 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d4.vin2a_d4 */
	{ VIN2A_D5, (M0 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d5.vin2a_d5 */
	{ VIN2A_D6, (M0 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d6.vin2a_d6 */
	{ VIN2A_D7, (M0 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d7.vin2a_d7 */
	{ VIN2A_D22, (M5 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d22.vin3a_hsync0 */
	{ VIN2A_D23, (M5 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d23.vin3a_vsync0 */
	{ XREF_CLK1, (M7 | PIN_INPUT | MANUAL_MODE) },	/* xref_clk1.vin6a_clk0 */
	{ MCASP1_AXR0, (M7 | PIN_INPUT | MANUAL_MODE) },	/* mcasp1_axr0.vin6a_vsync0 */
	{ MCASP1_AXR1, (M7 | PIN_INPUT | MANUAL_MODE) },	/* mcasp1_axr1.vin6a_hsync0 */
	{ MCASP2_ACLKX, (M7 | PIN_INPUT | MANUAL_MODE) },	/* mcasp2_aclkx.vin6a_d7 */
	{ MCASP2_FSX, (M7 | PIN_INPUT | MANUAL_MODE) },	/* mcasp2_fsx.vin6a_d6 */
	{ MCASP2_AXR2, (M7 | PIN_INPUT | MANUAL_MODE) },	/* mcasp2_axr2.vin6a_d5 */
	{ MCASP2_AXR3, (M7 | PIN_INPUT | MANUAL_MODE) },	/* mcasp2_axr3.vin6a_d4 */
	{ MCASP3_ACLKX, (M7 | PIN_INPUT | MANUAL_MODE) },	/* mcasp3_aclkx.vin6a_d3 */
	{ MCASP3_FSX, (M7 | PIN_INPUT | MANUAL_MODE) },	/* mcasp3_fsx.vin6a_d2 */
	{ MCASP3_AXR0, (M7 | PIN_INPUT | MANUAL_MODE) },	/* mcasp3_axr0.vin6a_d1 */
	{ MCASP3_AXR1, (M7 | PIN_INPUT | MANUAL_MODE) },	/* mcasp3_axr1.vin6a_d0 */
	{ GPIO6_10, (M9 | PIN_INPUT | MANUAL_MODE) },	/* gpio6_10.vin5a_clk0 */
	{ MMC3_CLK, (M9 | PIN_INPUT | MANUAL_MODE) },	/* mmc3_clk.vin5a_d7 */
	{ MMC3_CMD, (M9 | PIN_INPUT | MANUAL_MODE) },	/* mmc3_cmd.vin5a_d6 */
	{ MMC3_DAT0, (M9 | PIN_INPUT | MANUAL_MODE) },	/* mmc3_dat0.vin5a_d5 */
	{ MMC3_DAT1, (M9 | PIN_INPUT | MANUAL_MODE) },	/* mmc3_dat1.vin5a_d4 */
	{ MMC3_DAT2, (M9 | PIN_INPUT | MANUAL_MODE) },	/* mmc3_dat2.vin5a_d3 */
	{ MMC3_DAT3, (M9 | PIN_INPUT | MANUAL_MODE) },	/* mmc3_dat3.vin5a_d2 */
	{ MMC3_DAT4, (M9 | PIN_INPUT | MANUAL_MODE) },	/* mmc3_dat4.vin5a_d1 */
	{ MMC3_DAT5, (M9 | PIN_INPUT | MANUAL_MODE) },	/* mmc3_dat5.vin5a_d0 */
	{ MMC3_DAT6, (M9 | PIN_INPUT | MANUAL_MODE) },	/* mmc3_dat6.vin5a_hsync0 */
	{ MMC3_DAT7, (M9 | PIN_INPUT | MANUAL_MODE) },	/* mmc3_dat7.vin5a_vsync0 */
#endif

};

#ifdef CONFIG_IODELAY_RECALIBRATION
const struct iodelay_cfg_entry dra742_es1_1_iodelay_cfg_array[] = {
	{0x06F0, 480, 0},	/* CFG_RGMII0_RXC_IN */
	{0x06FC, 111, 1641},	/* CFG_RGMII0_RXCTL_IN */
	{0x0708, 272, 1116},	/* CFG_RGMII0_RXD0_IN */
	{0x0714, 243, 1260},	/* CFG_RGMII0_RXD1_IN */
	{0x0720, 0, 1614},	/* CFG_RGMII0_RXD2_IN */
	{0x072C, 105, 1673},	/* CFG_RGMII0_RXD3_IN */
	{0x0740, 0, 0},		/* CFG_RGMII0_TXC_OUT */
	{0x074C, 1560, 120},	/* CFG_RGMII0_TXCTL_OUT */
	{0x0758, 1570, 120},	/* CFG_RGMII0_TXD0_OUT */
	{0x0764, 1500, 120},	/* CFG_RGMII0_TXD1_OUT */
	{0x0770, 1775, 120},	/* CFG_RGMII0_TXD2_OUT */
	{0x077C, 1875, 120},	/* CFG_RGMII0_TXD3_OUT */
	{0x08D0, 0, 0},		/* CFG_VIN1A_CLK0_IN */
	{0x08DC, 2600, 0},	/* CFG_VIN1A_D0_IN */
	{0x08E8, 2652, 46},	/* CFG_VIN1A_D10_IN */
	{0x08F4, 2541, 0},	/* CFG_VIN1A_D11_IN */
	{0x0900, 2603, 574},	/* CFG_VIN1A_D12_IN */
	{0x090C, 2548, 443},	/* CFG_VIN1A_D13_IN */
	{0x0918, 2624, 598},	/* CFG_VIN1A_D14_IN */
	{0x0924, 2535, 1027},	/* CFG_VIN1A_D15_IN */
	{0x0930, 2526, 818},	/* CFG_VIN1A_D16_IN */
	{0x093C, 2623, 797},	/* CFG_VIN1A_D17_IN */
	{0x0948, 2578, 888},	/* CFG_VIN1A_D18_IN */
	{0x0954, 2574, 1008},	/* CFG_VIN1A_D19_IN */
	{0x0960, 2527, 123},	/* CFG_VIN1A_D1_IN */
	{0x096C, 2577, 737},	/* CFG_VIN1A_D20_IN */
	{0x0978, 2627, 616},	/* CFG_VIN1A_D21_IN */
	{0x0984, 2573, 777},	/* CFG_VIN1A_D22_IN */
	{0x0990, 2730, 67},	/* CFG_VIN1A_D23_IN */
	{0x099C, 2509, 303},	/* CFG_VIN1A_D2_IN */
	{0x09A8, 2494, 267},	/* CFG_VIN1A_D3_IN */
	{0x09B4, 2474, 0},	/* CFG_VIN1A_D4_IN */
	{0x09C0, 2556, 181},	/* CFG_VIN1A_D5_IN */
	{0x09CC, 2516, 195},	/* CFG_VIN1A_D6_IN */
	{0x09D8, 2589, 210},	/* CFG_VIN1A_D7_IN */
	{0x09E4, 2624, 75},	/* CFG_VIN1A_D8_IN */
	{0x09F0, 2704, 14},	/* CFG_VIN1A_D9_IN */
	{0x09FC, 2469, 55},	/* CFG_VIN1A_DE0_IN */
	{0x0A08, 2557, 264},	/* CFG_VIN1A_FLD0_IN */
	{0x0A14, 2465, 269},	/* CFG_VIN1A_HSYNC0_IN */
	{0x0A20, 2411, 348},	/* CFG_VIN1A_VSYNC0_IN */
	{0x0A70, 150, 0},	/* CFG_VIN2A_D12_OUT */
	{0x0A7C, 1500, 0},	/* CFG_VIN2A_D13_OUT */
	{0x0A88, 1600, 0},	/* CFG_VIN2A_D14_OUT */
	{0x0A94, 900, 0},	/* CFG_VIN2A_D15_OUT */
	{0x0AA0, 680, 0},	/* CFG_VIN2A_D16_OUT */
	{0x0AAC, 500, 0},	/* CFG_VIN2A_D17_OUT */
	{0x0AB0, 702, 0},	/* CFG_VIN2A_D18_IN */
	{0x0ABC, 136, 976},	/* CFG_VIN2A_D19_IN */
	{0x0AD4, 210, 1357},	/* CFG_VIN2A_D20_IN */
	{0x0AE0, 189, 1462},	/* CFG_VIN2A_D21_IN */
	{0x0AEC, 232, 1278},	/* CFG_VIN2A_D22_IN */
	{0x0AF8, 0, 1397},	/* CFG_VIN2A_D23_IN */
	{0x0144, 0, 0},		/* CFG_GPMC_A13_IN */
	{0x0150, 1976, 1389},	/* CFG_GPMC_A14_IN */
	{0x015C, 1872, 1408},	/* CFG_GPMC_A15_IN */
	{0x0168, 1914, 1506},	/* CFG_GPMC_A16_IN */
	{0x0170, 57, 0},	/* CFG_GPMC_A16_OUT */
	{0x0174, 1904, 1471},	/* CFG_GPMC_A17_IN */
	{0x0188, 1690, 0},	/* CFG_GPMC_A18_OUT */
	{0x0374, 0, 0},		/* CFG_GPMC_CS2_OUT */

#ifdef CONFIG_DRA7XX_VISION
	{ 0x0A2C,     0,     0 },	/* CFG_VIN1B_CLK1_IN : VIN3A_CLK0 - VIP2_MANUAL2 */
	{ 0x0930,  2805,   459 },	/* CFG_VIN1A_D16_IN : VIN3A_D0 - VIP2_MANUAL2 */
	{ 0x093C,  2904,   360 },	/* CFG_VIN1A_D17_IN : VIN3A_D1 - VIP2_MANUAL2 */
	{ 0x0948,  2857,   527 },	/* CFG_VIN1A_D18_IN : VIN3A_D2 - VIP2_MANUAL2 */
	{ 0x0954,  2861,   517 },	/* CFG_VIN1A_D19_IN : VIN3A_D3 - VIP2_MANUAL2 */
	{ 0x096C,  2855,   344 },	/* CFG_VIN1A_D20_IN : VIN3A_D4 - VIP2_MANUAL2 */
	{ 0x0978,  2908,   248 },	/* CFG_VIN1A_D21_IN : VIN3A_D5 - VIP2_MANUAL2 */
	{ 0x0984,  2843,   191 },	/* CFG_VIN1A_D22_IN : VIN3A_D6 - VIP2_MANUAL2 */
	{ 0x0990,  2683,     0 },	/* CFG_VIN1A_D23_IN : VIN3A_D7 - VIP2_MANUAL2 */
	{ 0x0A38,     0,     0 },	/* CFG_VIN2A_CLK0_IN : VIN2A_CLK0 - VIP1_MANUAL2 */
	{ 0x0B7C,  2174,     0 },	/* CFG_VIN2A_HSYNC0_IN : VIN2A_HSYNC0 - VIP1_MANUAL2 */
	{ 0x0B88,  1924,     0 },	/* CFG_VIN2A_VSYNC0_IN : VIN2A_VSYNC0 - VIP1_MANUAL2 */
	{ 0x0A44,  2090,     0 },	/* CFG_VIN2A_D0_IN : VIN2A_D0 - VIP1_MANUAL2 */
	{ 0x0AC8,  2481,     0 },	/* CFG_VIN2A_D1_IN : VIN2A_D1 - VIP1_MANUAL2 */
	{ 0x0B04,  1970,     0 },	/* CFG_VIN2A_D2_IN : VIN2A_D2 - VIP1_MANUAL2 */
	{ 0x0B10,  2525,     0 },	/* CFG_VIN2A_D3_IN : VIN2A_D3 - VIP1_MANUAL2 */
	{ 0x0B1C,  1981,     0 },	/* CFG_VIN2A_D4_IN : VIN2A_D4 - VIP1_MANUAL2 */
	{ 0x0B28,  2510,     0 },	/* CFG_VIN2A_D5_IN : VIN2A_D5 - VIP1_MANUAL2 */
	{ 0x0B34,  1769,     0 },	/* CFG_VIN2A_D6_IN : VIN2A_D6 - VIP1_MANUAL2 */
	{ 0x0B40,  2080,     0 },	/* CFG_VIN2A_D7_IN : VIN2A_D7 - VIP1_MANUAL2 */
	{ 0x0AEC,  1606,     0 },	/* CFG_VIN2A_D22_IN : VIN3A_HSYNC0 - VIP2_MANUAL2 */
	{ 0x0AF8,  1673,     0 },	/* CFG_VIN2A_D23_IN : VIN3A_VSYNC0 - VIP2_MANUAL2 */
	{ 0x0CFC,     0,     0 },	/* CFG_XREF_CLK1_IN : VIN6A_CLK0 - VIP3_MANUAL2 */
	{ 0x03C0,  3386,   618 },	/* CFG_MCASP1_AXR0_IN : VIN6A_VSYNC0 - VIP3_MANUAL2 */
	{ 0x0414,  3215,     0 },	/* CFG_MCASP1_AXR1_IN : VIN6A_HSYNC0 - VIP3_MANUAL2 */
	{ 0x04A4,  2171,     0 },	/* CFG_MCASP2_ACLKX_IN : VIN6A_D7 - VIP3_MANUAL2 */
	{ 0x051C,  2508,     0 },	/* CFG_MCASP2_FSX_IN : VIN6A_D6 - VIP3_MANUAL2 */
	{ 0x04C8,  2393,     0 },	/* CFG_MCASP2_AXR2_IN : VIN6A_D5 - VIP3_MANUAL2 */
	{ 0x04D4,  3010,     0 },	/* CFG_MCASP2_AXR3_IN : VIN6A_D4 - VIP3_MANUAL2 */
	{ 0x0528,  1029,     0 },	/* CFG_MCASP3_ACLKX_IN : VIN6A_D3 - VIP3_MANUAL2 */
	{ 0x054C,  2752,     0 },	/* CFG_MCASP3_FSX_IN : VIN6A_D2 - VIP3_MANUAL2 */
	{ 0x0534,  2603,     0 },	/* CFG_MCASP3_AXR0_IN : VIN6A_D1 - VIP3_MANUAL2 */
	{ 0x0540,  1821,   268 },	/* CFG_MCASP3_AXR1_IN : VIN6A_D0 - VIP3_MANUAL2 */
	{ 0x00D8,  1872,  2451 },	/* CFG_GPIO6_10_IN : VIN5A_CLK0 - VIP3_MANUAL2 */
	{ 0x0678,  5071,  1118 },	/* CFG_MMC3_CLK_IN : VIN5A_D7 - VIP3_MANUAL2 */
	{ 0x0684,  4978,  1147 },	/* CFG_MMC3_CMD_IN : VIN5A_D6 - VIP3_MANUAL2 */
	{ 0x0690,  4869,  1199 },	/* CFG_MMC3_DAT0_IN : VIN5A_D5 - VIP3_MANUAL2 */
	{ 0x069C,  4858,  1047 },	/* CFG_MMC3_DAT1_IN : VIN5A_D4 - VIP3_MANUAL2 */
	{ 0x06A8,  4986,   677 },	/* CFG_MMC3_DAT2_IN : VIN5A_D3 - VIP3_MANUAL2 */
	{ 0x06B4,  5018,  1313 },	/* CFG_MMC3_DAT3_IN : VIN5A_D2 - VIP3_MANUAL2 */
	{ 0x06C0,  5000,   888 },	/* CFG_MMC3_DAT4_IN : VIN5A_D1 - VIP3_MANUAL2 */
	{ 0x06CC,  4966,   874 },	/* CFG_MMC3_DAT5_IN : VIN5A_D0 - VIP3_MANUAL2 */
	{ 0x06D8,  4876,   941 },	/* CFG_MMC3_DAT6_IN : VIN5A_HSYNC0 - VIP3_MANUAL2 */
	{ 0x06E4,  5025,   540 },	/* CFG_MMC3_DAT7_IN : VIN5A_VSYNC0 - VIP3_MANUAL2 */
#endif
	DRA74x_MMC2_DELAY_CONF_ES11
};

const struct iodelay_cfg_entry dra742_es2_0_iodelay_cfg_array[] = {
	{0x06F0, 471, 0},	/* CFG_RGMII0_RXC_IN */
	{0x06FC, 30, 1919},	/* CFG_RGMII0_RXCTL_IN */
	{0x0708, 74, 1688},	/* CFG_RGMII0_RXD0_IN */
	{0x0714, 94, 1697},	/* CFG_RGMII0_RXD1_IN */
	{0x0720, 0, 1703},	/* CFG_RGMII0_RXD2_IN */
	{0x072C, 70, 1804},	/* CFG_RGMII0_RXD3_IN */
	{0x0740, 70, 70},	/* CFG_RGMII0_TXC_OUT */
	{0x074C, 35, 70},	/* CFG_RGMII0_TXCTL_OUT */
	{0x0758, 100, 130},	/* CFG_RGMII0_TXD0_OUT */
	{0x0764, 0, 70},	/* CFG_RGMII0_TXD1_OUT */
	{0x0770, 0, 0},	/* CFG_RGMII0_TXD2_OUT */
	{0x077C, 100, 130},	/* CFG_RGMII0_TXD3_OUT */
	{0x08D0, 0, 0},	/* CFG_VIN1A_CLK0_IN */
	{0x08DC, 2105, 619},	/* CFG_VIN1A_D0_IN */
	{0x08E8, 2107, 739},	/* CFG_VIN1A_D10_IN */
	{0x08F4, 2005, 788},	/* CFG_VIN1A_D11_IN */
	{0x0900, 2059, 1297},	/* CFG_VIN1A_D12_IN */
	{0x090C, 2027, 1141},	/* CFG_VIN1A_D13_IN */
	{0x0918, 2071, 1332},	/* CFG_VIN1A_D14_IN */
	{0x0924, 1995, 1764},	/* CFG_VIN1A_D15_IN */
	{0x0930, 1999, 1542},	/* CFG_VIN1A_D16_IN */
	{0x093C, 2072, 1540},	/* CFG_VIN1A_D17_IN */
	{0x0948, 2034, 1629},	/* CFG_VIN1A_D18_IN */
	{0x0954, 2026, 1761},	/* CFG_VIN1A_D19_IN */
	{0x0960, 2017, 757},	/* CFG_VIN1A_D1_IN */
	{0x096C, 2037, 1469},	/* CFG_VIN1A_D20_IN */
	{0x0978, 2077, 1349},	/* CFG_VIN1A_D21_IN */
	{0x0984, 2022, 1545},	/* CFG_VIN1A_D22_IN */
	{0x0990, 2168, 784},	/* CFG_VIN1A_D23_IN */
	{0x099C, 1996, 962},	/* CFG_VIN1A_D2_IN */
	{0x09A8, 1993, 901},	/* CFG_VIN1A_D3_IN */
	{0x09B4, 2098, 499},	/* CFG_VIN1A_D4_IN */
	{0x09C0, 2038, 844},	/* CFG_VIN1A_D5_IN */
	{0x09CC, 2002, 863},	/* CFG_VIN1A_D6_IN */
	{0x09D8, 2063, 873},	/* CFG_VIN1A_D7_IN */
	{0x09E4, 2088, 759},	/* CFG_VIN1A_D8_IN */
	{0x09F0, 2152, 701},	/* CFG_VIN1A_D9_IN */
	{0x09FC, 1926, 728},	/* CFG_VIN1A_DE0_IN */
	{0x0A08, 2043, 937},	/* CFG_VIN1A_FLD0_IN */
	{0x0A14, 1978, 909},	/* CFG_VIN1A_HSYNC0_IN */
	{0x0A20, 1926, 987},	/* CFG_VIN1A_VSYNC0_IN */
	{0x0A70, 140, 0},	/* CFG_VIN2A_D12_OUT */
	{0x0A7C, 90, 70},	/* CFG_VIN2A_D13_OUT */
	{0x0A88, 0, 0},	/* CFG_VIN2A_D14_OUT */
	{0x0A94, 0, 0},	/* CFG_VIN2A_D15_OUT */
	{0x0AA0, 0, 70},	/* CFG_VIN2A_D16_OUT */
	{0x0AAC, 0, 0},	/* CFG_VIN2A_D17_OUT */
	{0x0AB0, 612, 0},	/* CFG_VIN2A_D18_IN */
	{0x0ABC, 4, 927},	/* CFG_VIN2A_D19_IN */
	{0x0AD4, 136, 1340},	/* CFG_VIN2A_D20_IN */
	{0x0AE0, 130, 1450},	/* CFG_VIN2A_D21_IN */
	{0x0AEC, 144, 1269},	/* CFG_VIN2A_D22_IN */
	{0x0AF8, 0, 1330},	/* CFG_VIN2A_D23_IN */
	{0x0144, 0, 0},		/* CFG_GPMC_A13_IN */
	{0x0150, 2575, 966},	/* CFG_GPMC_A14_IN */
	{0x015C, 2503, 889},	/* CFG_GPMC_A15_IN */
	{0x0168, 2528, 1007},	/* CFG_GPMC_A16_IN */
	{0x0170, 0, 0},		/* CFG_GPMC_A16_OUT */
	{0x0174, 2533, 980},	/* CFG_GPMC_A17_IN */
	{0x0188, 590, 0},	/* CFG_GPMC_A18_OUT */
	{0x0374, 0, 0},		/* CFG_GPMC_CS2_OUT */

#ifdef CONFIG_DRA7XX_VISION
	{ 0x00D8,   765,  2551 },	/* CFG_GPIO6_10_IN : VIN5A_CLK0 - VIP3_MANUAL2 */
	{ 0x03C0,  2459,   381 },	/* CFG_MCASP1_AXR0_IN : VIN6A_VSYNC0 - VIP3_MANUAL2 */
	{ 0x0414,  2098,     0 },	/* CFG_MCASP1_AXR1_IN : VIN6A_HSYNC0 - VIP3_MANUAL2 */
	{ 0x04A4,  1206,     0 },	/* CFG_MCASP2_ACLKX_IN : VIN6A_D7 - VIP3_MANUAL2 */
	{ 0x04C8,  1277,     0 },	/* CFG_MCASP2_AXR2_IN : VIN6A_D5 - VIP3_MANUAL2 */
	{ 0x04D4,  1888,    90 },	/* CFG_MCASP2_AXR3_IN : VIN6A_D4 - VIP3_MANUAL2 */
	{ 0x051C,  1424,     0 },	/* CFG_MCASP2_FSX_IN : VIN6A_D6 - VIP3_MANUAL2 */
	{ 0x0528,     0,     0 },	/* CFG_MCASP3_ACLKX_IN : VIN6A_D3 - VIP3_MANUAL2 */
	{ 0x0534,  1428,    88 },	/* CFG_MCASP3_AXR0_IN : VIN6A_D1 - VIP3_MANUAL2 */
	{ 0x0540,  1331,   254 },	/* CFG_MCASP3_AXR1_IN : VIN6A_D0 - VIP3_MANUAL2 */
	{ 0x054C,  1633,    54 },	/* CFG_MCASP3_FSX_IN : VIN6A_D2 - VIP3_MANUAL2 */
	{ 0x0678,  2915,  2475 },	/* CFG_MMC3_CLK_IN : VIN5A_D7 - VIP3_MANUAL2 */
	{ 0x0684,  2832,  2485 },	/* CFG_MMC3_CMD_IN : VIN5A_D6 - VIP3_MANUAL2 */
	{ 0x0690,  2743,  2526 },	/* CFG_MMC3_DAT0_IN : VIN5A_D5 - VIP3_MANUAL2 */
	{ 0x069C,  2749,  2346 },	/* CFG_MMC3_DAT1_IN : VIN5A_D4 - VIP3_MANUAL2 */
	{ 0x06A8,  1811,  3012 },	/* CFG_MMC3_DAT2_IN : VIN5A_D3 - VIP3_MANUAL2 */
	{ 0x06B4,  2872,  2683 },	/* CFG_MMC3_DAT3_IN : VIN5A_D2 - VIP3_MANUAL2 */
	{ 0x06C0,  2836,  2271 },	/* CFG_MMC3_DAT4_IN : VIN5A_D1 - VIP3_MANUAL2 */
	{ 0x06CC,  1771,  3271 },	/* CFG_MMC3_DAT5_IN : VIN5A_D0 - VIP3_MANUAL2 */
	{ 0x06D8,  2752,  2255 },	/* CFG_MMC3_DAT6_IN : VIN5A_HSYNC0 - VIP3_MANUAL2 */
	{ 0x06E4,  1881,  2844 },	/* CFG_MMC3_DAT7_IN : VIN5A_VSYNC0 - VIP3_MANUAL2 */
	{ 0x0930,  2244,  1202 },	/* CFG_VIN1A_D16_IN : VIN3A_D0 - VIP2_MANUAL2 */
	{ 0x093C,  2321,  1116 },	/* CFG_VIN1A_D17_IN : VIN3A_D1 - VIP2_MANUAL2 */
	{ 0x0948,  2280,  1288 },	/* CFG_VIN1A_D18_IN : VIN3A_D2 - VIP2_MANUAL2 */
	{ 0x0954,  2282,  1281 },	/* CFG_VIN1A_D19_IN : VIN3A_D3 - VIP2_MANUAL2 */
	{ 0x096C,  2284,  1090 },	/* CFG_VIN1A_D20_IN : VIN3A_D4 - VIP2_MANUAL2 */
	{ 0x0978,  2324,  1000 },	/* CFG_VIN1A_D21_IN : VIN3A_D5 - VIP2_MANUAL2 */
	{ 0x0984,  2278,   915 },	/* CFG_VIN1A_D22_IN : VIN3A_D6 - VIP2_MANUAL2 */
	{ 0x0990,  2423,   398 },	/* CFG_VIN1A_D23_IN : VIN3A_D7 - VIP2_MANUAL2 */
	{ 0x0A2C,     0,     0 },	/* CFG_VIN1B_CLK1_IN : VIN3A_CLK0 - VIP2_MANUAL2 */
	{ 0x0AEC,  1641,     0 },	/* CFG_VIN2A_D22_IN : VIN3A_HSYNC0 - VIP2_MANUAL2 */
	{ 0x0AF8,  1748,     0 },	/* CFG_VIN2A_D23_IN : VIN3A_VSYNC0 - VIP2_MANUAL2 */
	{ 0x0CFC,     0,     0 },	/* CFG_XREF_CLK1_IN : VIN6A_CLK0 - VIP3_MANUAL2 */
#endif
	DRA74x_MMC2_DELAY_CONF_ES20
};

const struct pad_conf_entry dra72x_core_padconf_array_common[] = {
	{ VOUT1_CLK, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_clk.vout1_clk */
	{ VOUT1_DE, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_de.vout1_de */
	{ VOUT1_HSYNC, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_hsync.vout1_hsync */
	{ VOUT1_VSYNC, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_vsync.vout1_vsync */
	{ VOUT1_D0, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d0.vout1_d0 */
	{ VOUT1_D1, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d1.vout1_d1 */
	{ VOUT1_D2, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d2.vout1_d2 */
	{ VOUT1_D3, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d3.vout1_d3 */
	{ VOUT1_D4, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d4.vout1_d4 */
	{ VOUT1_D5, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d5.vout1_d5 */
	{ VOUT1_D6, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d6.vout1_d6 */
	{ VOUT1_D7, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d7.vout1_d7 */
	{ VOUT1_D8, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d8.vout1_d8 */
	{ VOUT1_D9, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d9.vout1_d9 */
	{ VOUT1_D10, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d10.vout1_d10 */
	{ VOUT1_D11, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d11.vout1_d11 */
	{ VOUT1_D12, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d12.vout1_d12 */
	{ VOUT1_D13, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d13.vout1_d13 */
	{ VOUT1_D14, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d14.vout1_d14 */
	{ VOUT1_D15, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d15.vout1_d15 */
	{ VOUT1_D16, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d16.vout1_d16 */
	{ VOUT1_D17, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d17.vout1_d17 */
	{ VOUT1_D18, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d18.vout1_d18 */
	{ VOUT1_D19, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d19.vout1_d19 */
	{ VOUT1_D20, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d20.vout1_d20 */
	{ VOUT1_D21, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d21.vout1_d21 */
	{ VOUT1_D22, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d22.vout1_d22 */
	{ VOUT1_D23, (M0 | PIN_INPUT_PULLDOWN)},	/* vout1_d23.vout1_d23 */
	{ GPMC_AD0, (M0 | PIN_INPUT) },	/* gpmc_ad0.gpmc_ad0 */
	{ GPMC_AD1, (M0 | PIN_INPUT) },	/* gpmc_ad1.gpmc_ad1 */
	{ GPMC_AD2, (M0 | PIN_INPUT) },	/* gpmc_ad2.gpmc_ad2 */
	{ GPMC_AD3, (M0 | PIN_INPUT) },	/* gpmc_ad3.gpmc_ad3 */
	{ GPMC_AD4, (M0 | PIN_INPUT) },	/* gpmc_ad4.gpmc_ad4 */
	{ GPMC_AD5, (M0 | PIN_INPUT) },	/* gpmc_ad5.gpmc_ad5 */
	{ GPMC_AD6, (M0 | PIN_INPUT) },	/* gpmc_ad6.gpmc_ad6 */
	{ GPMC_AD7, (M0 | PIN_INPUT) },	/* gpmc_ad7.gpmc_ad7 */
	{ GPMC_AD8, (M0 | PIN_INPUT) },	/* gpmc_ad8.gpmc_ad8 */
	{ GPMC_AD9, (M0 | PIN_INPUT) },	/* gpmc_ad9.gpmc_ad9 */
	{ GPMC_AD10, (M0 | PIN_INPUT) },	/* gpmc_ad10.gpmc_ad10 */
	{ GPMC_AD11, (M0 | PIN_INPUT) },	/* gpmc_ad11.gpmc_ad11 */
	{ GPMC_AD12, (M0 | PIN_INPUT) },	/* gpmc_ad12.gpmc_ad12 */
	{ GPMC_AD13, (M0 | PIN_INPUT) },	/* gpmc_ad13.gpmc_ad13 */
	{ GPMC_AD14, (M0 | PIN_INPUT) },	/* gpmc_ad14.gpmc_ad14 */
	{ GPMC_AD15, (M0 | PIN_INPUT) },	/* gpmc_ad15.gpmc_ad15 */
	{ GPMC_A13, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* gpmc_a13.qspi1_rtclk */
	{ GPMC_A14, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* gpmc_a14.qspi1_d3 */
	{ GPMC_A15, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* gpmc_a15.qspi1_d2 */
	{ GPMC_A16, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* gpmc_a16.qspi1_d0 */
	{ GPMC_A17, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* gpmc_a17.qspi1_d1 */
	{ GPMC_A18, (M1 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* gpmc_a18.qspi1_sclk */
	{ GPMC_A19, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a19.mmc2_dat4 */
	{ GPMC_A20, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a20.mmc2_dat5 */
	{ GPMC_A21, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a21.mmc2_dat6 */
	{ GPMC_A22, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a22.mmc2_dat7 */
	{ GPMC_A23, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a23.mmc2_clk */
	{ GPMC_A24, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a24.mmc2_dat0 */
	{ GPMC_A25, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a25.mmc2_dat1 */
	{ GPMC_A26, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a26.mmc2_dat2 */
	{ GPMC_A27, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_a27.mmc2_dat3 */
	{ GPMC_CS1, (M1 | PIN_INPUT_PULLUP) },	/* gpmc_cs1.mmc2_cmd */
	{ GPMC_CS0, (M0 | PIN_OUTPUT) },	/* gpmc_cs0.gpmc_cs0 */
	{ GPMC_CS2, (M1 | PIN_INPUT_PULLUP | MANUAL_MODE) },	/* gpmc_cs2.qspi1_cs0 */
	{ GPMC_ADVN_ALE, (M0 | PIN_OUTPUT) },	/* gpmc_advn_ale.gpmc_advn_ale */
	{ GPMC_OEN_REN, (M0 | PIN_OUTPUT) },	/* gpmc_oen_ren.gpmc_oen_ren */
	{ GPMC_WEN, (M0 | PIN_OUTPUT) },	/* gpmc_wen.gpmc_wen */
	{ GPMC_BEN0, (M0 | PIN_OUTPUT) },	/* gpmc_ben0.gpmc_ben0 */
	{ GPMC_WAIT0, (M0 | PIN_INPUT | SLEWCONTROL) },	/* gpmc_wait0.gpmc_wait0 */
	{ VIN2A_CLK0, (M0 | PIN_INPUT | VIRTUAL_MODE9) },	/* vin2a_clk0.vin2a_clk0 */
	{ VIN2A_HSYNC0, (M0 | PIN_INPUT | VIRTUAL_MODE6) },	/* vin2a_hsync0.vin2a_hsync0 */
	{ VIN2A_VSYNC0, (M0 | PIN_INPUT | VIRTUAL_MODE9) },	/* vin2a_vsync0.vin2a_vsync0 */
	{ VIN2A_D0, (M0 | PIN_INPUT | VIRTUAL_MODE14) },	/* vin2a_d0.vin2a_d0 */
	{ VIN2A_D1, (M0 | PIN_INPUT | VIRTUAL_MODE14) },	/* vin2a_d1.vin2a_d1 */
	{ VIN2A_D2, (M0 | PIN_INPUT | VIRTUAL_MODE14) },	/* vin2a_d2.vin2a_d2 */
	{ VIN2A_D3, (M0 | PIN_INPUT | VIRTUAL_MODE8) },	/* vin2a_d3.vin2a_d3 */
	{ VIN2A_D4, (M0 | PIN_INPUT | VIRTUAL_MODE8) },	/* vin2a_d4.vin2a_d4 */
	{ VIN2A_D5, (M0 | PIN_INPUT | VIRTUAL_MODE8) },	/* vin2a_d5.vin2a_d5 */
	{ VIN2A_D6, (M0 | PIN_INPUT | VIRTUAL_MODE6) },	/* vin2a_d6.vin2a_d6 */
	{ VIN2A_D7, (M0 | PIN_INPUT | VIRTUAL_MODE6) },	/* vin2a_d7.vin2a_d7 */
	{ MDIO_MCLK, (M0 | PIN_OUTPUT_PULLUP | SLEWCONTROL) },	/* mdio_mclk.mdio_mclk */
	{ MDIO_D, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL) },	/* mdio_d.mdio_d */
	{ USB1_DRVVBUS, (M0 | PIN_INPUT_PULLDOWN | SLEWCONTROL) },	/* usb2_drvvbus.usb2_drvvbus */
	{ USB2_DRVVBUS, (M0 | PIN_INPUT_PULLDOWN | SLEWCONTROL) },	/* usb2_drvvbus.usb2_drvvbus */
	{ XREF_CLK2, (M5 | PIN_INPUT_PULLDOWN) },	/* xref_clk2.atl_clk2 */
	{ MCASP1_AXR0, (M10 | PIN_INPUT | SLEWCONTROL) },	/* mcasp1_axr0.i2c5_sda */
	{ MCASP1_AXR1, (M10 | PIN_INPUT | SLEWCONTROL) },	/* mcasp1_axr1.i2c5_scl */
	{ MCASP1_AXR2, (M14 | PIN_OUTPUT) },	/* mcasp1_axr2.gpio5_4 */
	{ MCASP1_AXR5, (M14 | PIN_INPUT_PULLDOWN) },	/* mcasp1_axr5.gpio5_7 */
	{ MCASP1_AXR6, (M14 | PIN_OUTPUT) },	/* mcasp1_axr6.gpio5_8 */
	{ MCASP1_AXR12, (M1 | PIN_INPUT | SLEWCONTROL | VIRTUAL_MODE10) },	/* mcasp1_axr12.mcasp7_axr0 */
	{ MCASP1_AXR13, (M1 | PIN_INPUT | SLEWCONTROL | VIRTUAL_MODE10) },	/* mcasp1_axr13.mcasp7_axr1 */
	{ MCASP1_AXR14, (M1 | PIN_INPUT | SLEWCONTROL | VIRTUAL_MODE10) },	/* mcasp1_axr14.mcasp7_aclkx */
	{ MCASP1_AXR15, (M1 | PIN_INPUT | SLEWCONTROL | VIRTUAL_MODE10) },	/* mcasp1_axr15.mcasp7_fsx */
	{ MCASP3_ACLKX, (M0 | PIN_INPUT_PULLDOWN) },	/* mcasp3_aclkx.mcasp3_aclkx */
	{ MCASP3_FSX, (M0 | PIN_INPUT | SLEWCONTROL) },	/* mcasp3_fsx.mcasp3_fsx */
	{ MCASP3_AXR0, (M0 | PIN_INPUT | SLEWCONTROL) },	/* mcasp3_axr0.mcasp3_axr0 */
	{ MCASP3_AXR1, (M0 | PIN_INPUT | SLEWCONTROL) },	/* mcasp3_axr1.mcasp3_axr1 */
	DRA72x_MMC1_PAD_CONF
	DRA72x_MMC2_PAD_CONF
	{ MMC1_SDCD, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL) },	/* mmc1_sdcd.mmc1_sdcd */
	{ MMC1_SDWP, (M14 | PIN_INPUT | SLEWCONTROL) },	/* mmc1_sdwp.gpio6_28 */
	{ SPI1_CS1, (M14 | PIN_OUTPUT) },	/* spi1_cs1.gpio7_11 */
	{ SPI1_CS2, (M14 | PIN_INPUT_PULLDOWN | SLEWCONTROL) },	/* spi1_cs2.gpio7_12 */
	{ SPI2_SCLK, (M1 | PIN_INPUT_PULLUP) },	/* spi2_sclk.uart3_rxd */
	{ SPI2_D1, (M1 | PIN_OUTPUT_PULLDOWN | SLEWCONTROL) },	/* spi2_d1.uart3_txd */
	{ SPI2_D0, (M1 | PIN_INPUT | SLEWCONTROL) },	/* spi2_d0.uart3_ctsn */
	{ SPI2_CS0, (M1 | PIN_OUTPUT_PULLDOWN | SLEWCONTROL) },	/* spi2_cs0.uart3_rtsn */
	{ UART1_RXD, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL) },	/* uart1_rxd.uart1_rxd */
	{ UART1_TXD, (M0 | PIN_INPUT_PULLUP | SLEWCONTROL) },	/* uart1_txd.uart1_txd */
	{ UART1_CTSN, (M3 | PIN_INPUT_PULLUP) },	/* uart1_ctsn.mmc4_clk */
	{ UART1_RTSN, (M3 | PIN_INPUT_PULLUP) },	/* uart1_rtsn.mmc4_cmd */
	{ UART2_RXD, (M3 | PIN_INPUT_PULLUP) },	/* uart2_rxd.mmc4_dat0 */
	{ UART2_TXD, (M3 | PIN_INPUT_PULLUP) },	/* uart2_txd.mmc4_dat1 */
	{ UART2_CTSN, (M3 | PIN_INPUT_PULLUP) },	/* uart2_ctsn.mmc4_dat2 */
	{ UART2_RTSN, (M3 | PIN_INPUT_PULLUP) },	/* uart2_rtsn.mmc4_dat3 */
	{ I2C2_SDA, (M1 | PIN_INPUT) },	/* i2c2_sda.hdmi1_ddc_scl */
	{ I2C2_SCL, (M1 | PIN_INPUT) },	/* i2c2_scl.hdmi1_ddc_sda */
	{ WAKEUP3, (M1 | PIN_INPUT_PULLUP) },	/* wakeup3.sys_nirq1 */
#ifdef CONFIG_DRA7XX_JAMR3
	{ XREF_CLK1, (M5 | PIN_INPUT_PULLDOWN) },	/* xref_clk1.atl_clk1 */
	{ XREF_CLK3, (M14 | PIN_INPUT)},	/* xref_clk3.gpio6_20 */
	{ MCASP1_AXR8, (M1 | PIN_OUTPUT_PULLDOWN | SLEWCONTROL) },	/* mcasp1_axr8.mcasp6_axr0 */
	{ MCASP1_AXR9, (M1 | PIN_INPUT | SLEWCONTROL) },	/* mcasp1_axr9.mcasp6_axr1 */
	{ MCASP1_AXR10, (M1 | PIN_INPUT | SLEWCONTROL) },	/* mcasp1_axr10.mcasp6_aclkx */
	{ MCASP1_AXR11, (M1 | PIN_INPUT | SLEWCONTROL) },	/* mcasp1_axr11.mcasp6_fsx */
	{ MCASP2_ACLKX, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE10) },	/* mcasp2_aclkx.mcasp2_aclkx */
	{ MCASP2_FSX, (M0 | PIN_INPUT | SLEWCONTROL | VIRTUAL_MODE10) },	/* mcasp2_fsx.mcasp2_fsx */
	{ MCASP2_AXR0, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE12) },	/* mcasp2_axr0.mcasp2_axr0 */
	{ MCASP2_AXR1, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE12) },	/* mcasp2_axr1.mcasp2_axr1 */
	{ MCASP2_AXR2, (M0 | PIN_INPUT_PULLDOWN | SLEWCONTROL | VIRTUAL_MODE10) },	/* mcasp2_axr2.mcasp2_axr2 */
	{ MCASP2_AXR3, (M0 | PIN_INPUT_PULLDOWN | SLEWCONTROL | VIRTUAL_MODE10) },	/* mcasp2_axr3.mcasp2_axr3 */
	{ MCASP2_AXR4, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE12) },	/* mcasp2_axr4.mcasp2_axr4 */
	{ MCASP2_AXR5, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE12) },	/* mcasp2_axr5.mcasp2_axr5 */
	{ MCASP2_AXR6, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE12) },	/* mcasp2_axr6.mcasp2_axr6 */
	{ MCASP2_AXR7, (M0 | PIN_INPUT_PULLDOWN | VIRTUAL_MODE12) },	/* mcasp2_axr7.mcasp2_axr7 */
	{ MCASP4_ACLKX, (M4 | PIN_INPUT_PULLUP)},	/* mcasp4_aclkx.i2c4_sda */
	{ MCASP4_FSX, (M4 | PIN_INPUT_PULLUP)},	/* mcasp4_fsx.i2c4_scl */
#endif
};

const struct pad_conf_entry dra72x_rgmii_padconf_array_revb[] = {
	{ RGMII0_TXC, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* rgmii0_txc.rgmii0_txc */
	{ RGMII0_TXCTL, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* rgmii0_txctl.rgmii0_txctl */
	{ RGMII0_TXD3, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* rgmii0_txd3.rgmii0_txd3 */
	{ RGMII0_TXD2, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* rgmii0_txd2.rgmii0_txd2 */
	{ RGMII0_TXD1, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* rgmii0_txd1.rgmii0_txd1 */
	{ RGMII0_TXD0, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* rgmii0_txd0.rgmii0_txd0 */
	{ RGMII0_RXC, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* rgmii0_rxc.rgmii0_rxc */
	{ RGMII0_RXCTL, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* rgmii0_rxctl.rgmii0_rxctl */
	{ RGMII0_RXD3, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* rgmii0_rxd3.rgmii0_rxd3 */
	{ RGMII0_RXD2, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* rgmii0_rxd2.rgmii0_rxd2 */
	{ RGMII0_RXD1, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* rgmii0_rxd1.rgmii0_rxd1 */
	{ RGMII0_RXD0, (M0 | PIN_INPUT_PULLDOWN | MANUAL_MODE) },	/* rgmii0_rxd0.rgmii0_rxd0 */
	{ VIN2A_D12, (M3 | PIN_OUTPUT | MANUAL_MODE) },	/* vin2a_d12.rgmii1_txc */
	{ VIN2A_D13, (M3 | PIN_OUTPUT | MANUAL_MODE) },	/* vin2a_d13.rgmii1_txctl */
	{ VIN2A_D14, (M3 | PIN_OUTPUT | MANUAL_MODE) },	/* vin2a_d14.rgmii1_txd3 */
	{ VIN2A_D15, (M3 | PIN_OUTPUT | MANUAL_MODE) },	/* vin2a_d15.rgmii1_txd2 */
	{ VIN2A_D16, (M3 | PIN_OUTPUT | MANUAL_MODE) },	/* vin2a_d16.rgmii1_txd1 */
	{ VIN2A_D17, (M3 | PIN_OUTPUT | MANUAL_MODE) },	/* vin2a_d17.rgmii1_txd0 */
	{ VIN2A_D18, (M3 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d18.rgmii1_rxc */
	{ VIN2A_D19, (M3 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d19.rgmii1_rxctl */
	{ VIN2A_D20, (M3 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d20.rgmii1_rxd3 */
	{ VIN2A_D21, (M3 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d21.rgmii1_rxd2 */
	{ VIN2A_D22, (M3 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d22.rgmii1_rxd1 */
	{ VIN2A_D23, (M3 | PIN_INPUT | MANUAL_MODE) },	/* vin2a_d23.rgmii1_rxd0 */
};

const struct pad_conf_entry dra72x_rgmii_padconf_array_revc[] = {
	{RGMII0_TXC, (M0 | PIN_OUTPUT)},	/* rgmii0_txc.rgmii0_txc */
	{RGMII0_TXCTL, (M0 | PIN_OUTPUT)},	/* rgmii0_txctl.rgmii0_txctl */
	{RGMII0_TXD3, (M0 | PIN_OUTPUT)},	/* rgmii0_txd3.rgmii0_txd3 */
	{RGMII0_TXD2, (M0 | PIN_OUTPUT)},	/* rgmii0_txd2.rgmii0_txd2 */
	{RGMII0_TXD1, (M0 | PIN_OUTPUT)},	/* rgmii0_txd1.rgmii0_txd1 */
	{RGMII0_TXD0, (M0 | PIN_OUTPUT)},	/* rgmii0_txd0.rgmii0_txd0 */
	{RGMII0_RXC, (M0 | PIN_INPUT_PULLDOWN)},	/* rgmii0_rxc.rgmii0_rxc */
	{RGMII0_RXCTL, (M0 | PIN_INPUT_PULLDOWN)},	/* rgmii0_rxctl.rgmii0_rxctl */
	{RGMII0_RXD3, (M0 | PIN_INPUT_PULLDOWN)},	/* rgmii0_rxd3.rgmii0_rxd3 */
	{RGMII0_RXD2, (M0 | PIN_INPUT_PULLDOWN)},	/* rgmii0_rxd2.rgmii0_rxd2 */
	{RGMII0_RXD1, (M0 | PIN_INPUT_PULLDOWN)},	/* rgmii0_rxd1.rgmii0_rxd1 */
	{RGMII0_RXD0, (M0 | PIN_INPUT_PULLDOWN)},	/* rgmii0_rxd0.rgmii0_rxd0 */
	{VIN2A_D12, (M3 | PIN_OUTPUT)},	/* vin2a_d12.rgmii1_txc */
	{VIN2A_D13, (M3 | PIN_OUTPUT)},	/* vin2a_d13.rgmii1_txctl */
	{VIN2A_D14, (M3 | PIN_OUTPUT)},	/* vin2a_d14.rgmii1_txd3 */
	{VIN2A_D15, (M3 | PIN_OUTPUT)},	/* vin2a_d15.rgmii1_txd2 */
	{VIN2A_D16, (M3 | PIN_OUTPUT)},	/* vin2a_d16.rgmii1_txd1 */
	{VIN2A_D17, (M3 | PIN_OUTPUT)},	/* vin2a_d17.rgmii1_txd0 */
	{VIN2A_D18, (M3 | PIN_INPUT_PULLDOWN)},	/* vin2a_d18.rgmii1_rxc */
	{VIN2A_D19, (M3 | PIN_INPUT_PULLDOWN)},	/* vin2a_d19.rgmii1_rxctl */
	{VIN2A_D20, (M3 | PIN_INPUT_PULLDOWN)},	/* vin2a_d20.rgmii1_rxd3 */
	{VIN2A_D21, (M3 | PIN_INPUT_PULLDOWN)},	/* vin2a_d21.rgmii1_rxd2 */
	{VIN2A_D22, (M3 | PIN_INPUT_PULLDOWN)},	/* vin2a_d22.rgmii1_rxd1 */
	{VIN2A_D23, (M3 | PIN_INPUT_PULLDOWN)},	/* vin2a_d23.rgmii1_rxd0 */

};

const struct pad_conf_entry dra72x_vision_padconf_array_revb[] = {
#ifdef CONFIG_DRA7XX_VISION
	/* vin1a */
	{ GPIO6_10, (M9 | PIN_INPUT | VIRTUAL_MODE7) },	/* gpio6_10.vin1a_clk0 */
	{ MMC3_CLK, (M9 | PIN_INPUT | VIRTUAL_MODE6) },	/* mmc3_clk.vin1a_d7 */
	{ MMC3_CMD, (M9 | PIN_INPUT | VIRTUAL_MODE6) },	/* mmc3_cmd.vin1a_d6 */
	{ MMC3_DAT0, (M9 | PIN_INPUT | VIRTUAL_MODE6) },	/* mmc3_dat0.vin1a_d5 */
	{ MMC3_DAT1, (M9 | PIN_INPUT | VIRTUAL_MODE6) },	/* mmc3_dat1.vin1a_d4 */
	{ MMC3_DAT2, (M9 | PIN_INPUT | VIRTUAL_MODE6) },	/* mmc3_dat2.vin1a_d3 */
	{ MMC3_DAT3, (M9 | PIN_INPUT | VIRTUAL_MODE6) },	/* mmc3_dat3.vin1a_d2 */
	{ MMC3_DAT4, (M9 | PIN_INPUT | VIRTUAL_MODE6) },	/* mmc3_dat4.vin1a_d1 */
	{ MMC3_DAT5, (M9 | PIN_INPUT | VIRTUAL_MODE6) },	/* mmc3_dat5.vin1a_d0 */
	{ MMC3_DAT6, (M9 | PIN_INPUT | VIRTUAL_MODE6) },	/* mmc3_dat6.vin1a_hsync0 */
	{ MMC3_DAT7, (M9 | PIN_INPUT | VIRTUAL_MODE6) },	/* mmc3_dat7.vin1a_vsync0 */

	/* vin1b */
	{ GPMC_A8, (M6 | PIN_INPUT | VIRTUAL_MODE14) },	/* gpmc_a8.vin1b_hsync1 */
	{ MDIO_MCLK, (M5 | PIN_INPUT | VIRTUAL_MODE10) },	/* mdio_mclk.vin1b_clk1 */
	{ MDIO_D, (M5 | PIN_INPUT | VIRTUAL_MODE10) },	/* mdio_d.vin1b_d0 */
	{ UART3_RXD, (M5 | PIN_INPUT | VIRTUAL_MODE10) },	/* uart3_rxd.vin1b_d1 */
	{ UART3_TXD, (M5 | PIN_INPUT | VIRTUAL_MODE10) },	/* uart3_txd.vin1b_d2 */
	{ RGMII0_TXC, (M5 | PIN_INPUT | VIRTUAL_MODE10) },	/* rgmii0_txc.vin1b_d3 */
	{ RGMII0_TXCTL, (M5 | PIN_INPUT | VIRTUAL_MODE10) },	/* rgmii0_txctl.vin1b_d4 */
	{ RGMII0_TXD1, (M5 | PIN_INPUT | VIRTUAL_MODE10) },	/* rgmii0_txd1.vin1b_vsync1 */
	{ RGMII0_RXC, (M5 | PIN_INPUT | VIRTUAL_MODE10) },	/* rgmii0_rxc.vin1b_d5 */
	{ RGMII0_RXCTL, (M5 | PIN_INPUT | VIRTUAL_MODE10) },	/* rgmii0_rxctl.vin1b_d6 */
	{ RGMII0_RXD3, (M5 | PIN_INPUT | VIRTUAL_MODE10) },	/* rgmii0_rxd3.vin1b_d7 */

	/* vin2a */
	{ VIN2A_CLK0, (M0 | PIN_INPUT | VIRTUAL_MODE9) },	/* vin2a_clk0.vin2a_clk0 */
	{ VIN2A_VSYNC0, (M0 | PIN_INPUT | VIRTUAL_MODE9) },	/* vin2a_vsync0.vin2a_vsync0 */
	{ VIN2A_D0, (M0 | PIN_INPUT | VIRTUAL_MODE14) },	/* vin2a_d0.vin2a_d0 */
	{ VIN2A_D1, (M0 | PIN_INPUT | VIRTUAL_MODE14) },	/* vin2a_d1.vin2a_d1 */
	{ VIN2A_D2, (M0 | PIN_INPUT | VIRTUAL_MODE14) },	/* vin2a_d2.vin2a_d2 */
	{ VIN2A_D3, (M0 | PIN_INPUT | VIRTUAL_MODE8) },	/* vin2a_d3.vin2a_d3 */
	{ VIN2A_D4, (M0 | PIN_INPUT | VIRTUAL_MODE8) },	/* vin2a_d4.vin2a_d4 */
	{ VIN2A_D5, (M0 | PIN_INPUT | VIRTUAL_MODE8) },	/* vin2a_d5.vin2a_d5 */
	{ VIN2A_D6, (M0 | PIN_INPUT | VIRTUAL_MODE6) },	/* vin2a_d6.vin2a_d6 */
	{ VIN2A_D7, (M0 | PIN_INPUT | VIRTUAL_MODE6) },	/* vin2a_d7.vin2a_d7 */
	{ RGMII0_TXD2, (M4 | PIN_INPUT | VIRTUAL_MODE10) },	/* rgmii0_txd2.vin2a_hsync0 */

	/* vin2b */
	{ VIN2A_FLD0, (M2 | PIN_INPUT | VIRTUAL_MODE9) },	/* vin2a_fld0.vin2b_clk1 */
	{ VIN2A_HSYNC0, (M3 | PIN_INPUT | VIRTUAL_MODE7) },	/* vin2a_hsync0.vin2b_hsync1 */
	{ VIN2A_D16, (M2 | PIN_INPUT | VIRTUAL_MODE6) },	/* vin2a_d16.vin2b_d7 */
	{ VIN2A_D17, (M2 | PIN_INPUT | VIRTUAL_MODE6) },	/* vin2a_d17.vin2b_d6 */
	{ VIN2A_D18, (M2 | PIN_INPUT | VIRTUAL_MODE6) },	/* vin2a_d18.vin2b_d5 */
	{ VIN2A_D19, (M2 | PIN_INPUT | VIRTUAL_MODE6) },	/* vin2a_d19.vin2b_d4 */
	{ VIN2A_D20, (M2 | PIN_INPUT | VIRTUAL_MODE6) },	/* vin2a_d20.vin2b_d3 */
	{ VIN2A_D21, (M2 | PIN_INPUT | VIRTUAL_MODE9) },	/* vin2a_d21.vin2b_d2 */
	{ VIN2A_D22, (M2 | PIN_INPUT | VIRTUAL_MODE9) },	/* vin2a_d22.vin2b_d1 */
	{ VIN2A_D23, (M2 | PIN_INPUT | VIRTUAL_MODE9) },	/* vin2a_d23.vin2b_d0 */
	{ GPIO6_11, (M4 | PIN_INPUT | VIRTUAL_MODE8) },	/* gpio6_11.vin2b_vsync1 */
#endif
};

const struct pad_conf_entry dra72x_vision_padconf_array_revc[] = {
#ifdef CONFIG_DRA7XX_VISION
	/* vin1a */
        { GPMC_AD0, (M2 | PIN_INPUT | VIRTUAL_MODE12) },        /* gpmc_ad0.vin1a_d0 */
        { GPMC_AD1, (M2 | PIN_INPUT | VIRTUAL_MODE12) },        /* gpmc_ad1.vin1a_d1 */
        { GPMC_AD2, (M2 | PIN_INPUT | VIRTUAL_MODE12) },        /* gpmc_ad2.vin1a_d2 */
        { GPMC_AD3, (M2 | PIN_INPUT | VIRTUAL_MODE12) },        /* gpmc_ad3.vin1a_d3 */
        { GPMC_AD4, (M2 | PIN_INPUT | VIRTUAL_MODE12) },        /* gpmc_ad4.vin1a_d4 */
        { GPMC_AD5, (M2 | PIN_INPUT | VIRTUAL_MODE12) },        /* gpmc_ad5.vin1a_d5 */
        { GPMC_AD6, (M2 | PIN_INPUT | VIRTUAL_MODE12) },        /* gpmc_ad6.vin1a_d6 */
        { GPMC_AD7, (M2 | PIN_INPUT | VIRTUAL_MODE12) },        /* gpmc_ad7.vin1a_d7 */
        { GPMC_A8, (M2 | PIN_INPUT | VIRTUAL_MODE12) }, /* gpmc_a8.vin1a_hsync0 */
        { GPMC_A9, (M2 | PIN_INPUT | VIRTUAL_MODE12) }, /* gpmc_a9.vin1a_vsync0 */
        { GPMC_CS3, (M2 | PIN_INPUT | VIRTUAL_MODE11) },        /* gpmc_cs3.vin1a_clk0 */

	/* vin1b */
        { MDIO_MCLK, (M5 | PIN_INPUT | SLEWCONTROL | VIRTUAL_MODE10) }, /* mdio_mclk.vin1b_clk1 */
        { MDIO_D, (M5 | PIN_INPUT | SLEWCONTROL | VIRTUAL_MODE10) },    /* mdio_d.vin1b_d0 */
        { UART3_RXD, (M5 | PIN_INPUT | SLEWCONTROL | VIRTUAL_MODE10) }, /* uart3_rxd.vin1b_d1 */
        { UART3_TXD, (M5 | PIN_INPUT | SLEWCONTROL | VIRTUAL_MODE10) }, /* uart3_txd.vin1b_d2 */
        { RGMII0_TXC, (M5 | PIN_INPUT | VIRTUAL_MODE10) },      /* rgmii0_txc.vin1b_d3 */
        { RGMII0_TXCTL, (M5 | PIN_INPUT | VIRTUAL_MODE10) },    /* rgmii0_txctl.vin1b_d4 */
        { RGMII0_TXD2, (M5 | PIN_INPUT | VIRTUAL_MODE10) },     /* rgmii0_txd2.vin1b_hsync1 */
        { RGMII0_TXD1, (M5 | PIN_INPUT | VIRTUAL_MODE10) },     /* rgmii0_txd1.vin1b_vsync1 */
        { RGMII0_RXC, (M5 | PIN_INPUT | VIRTUAL_MODE10) },      /* rgmii0_rxc.vin1b_d5 */
        { RGMII0_RXCTL, (M5 | PIN_INPUT | VIRTUAL_MODE10) },    /* rgmii0_rxctl.vin1b_d6 */
        { RGMII0_RXD3, (M5 | PIN_INPUT | VIRTUAL_MODE10) },     /* rgmii0_rxd3.vin1b_d7 */

	/* vin2a */
        { VIN2A_CLK0, (M0 | PIN_INPUT | VIRTUAL_MODE9) },       /* vin2a_clk0.vin2a_clk0 */
        { VIN2A_HSYNC0, (M0 | PIN_INPUT | VIRTUAL_MODE6) },     /* vin2a_hsync0.vin2a_hsync0 */
        { VIN2A_VSYNC0, (M0 | PIN_INPUT | VIRTUAL_MODE9) },     /* vin2a_vsync0.vin2a_vsync0 */
        { VIN2A_D0, (M0 | PIN_INPUT | VIRTUAL_MODE14) },        /* vin2a_d0.vin2a_d0 */
        { VIN2A_D1, (M0 | PIN_INPUT | VIRTUAL_MODE14) },        /* vin2a_d1.vin2a_d1 */
        { VIN2A_D2, (M0 | PIN_INPUT | VIRTUAL_MODE14) },        /* vin2a_d2.vin2a_d2 */
        { VIN2A_D3, (M0 | PIN_INPUT | VIRTUAL_MODE8) }, /* vin2a_d3.vin2a_d3 */
        { VIN2A_D4, (M0 | PIN_INPUT | VIRTUAL_MODE8) }, /* vin2a_d4.vin2a_d4 */
        { VIN2A_D5, (M0 | PIN_INPUT | VIRTUAL_MODE8) }, /* vin2a_d5.vin2a_d5 */
        { VIN2A_D6, (M0 | PIN_INPUT | VIRTUAL_MODE6) }, /* vin2a_d6.vin2a_d6 */
        { VIN2A_D7, (M0 | PIN_INPUT | VIRTUAL_MODE6) }, /* vin2a_d7.vin2a_d7 */

	/* vin2b */
        { GPIO6_10, (M4 | PIN_INPUT | VIRTUAL_MODE8) }, /* gpio6_10.vin2b_hsync1 */
        { GPIO6_11, (M4 | PIN_INPUT | VIRTUAL_MODE8) }, /* gpio6_11.vin2b_vsync1 */
        { MMC3_CLK, (M4 | PIN_INPUT | VIRTUAL_MODE7) }, /* mmc3_clk.vin2b_d7 */
        { MMC3_CMD, (M4 | PIN_INPUT | VIRTUAL_MODE7) }, /* mmc3_cmd.vin2b_d6 */
        { MMC3_DAT0, (M4 | PIN_INPUT | VIRTUAL_MODE7) },        /* mmc3_dat0.vin2b_d5 */
        { MMC3_DAT1, (M4 | PIN_INPUT | VIRTUAL_MODE7) },        /* mmc3_dat1.vin2b_d4 */
        { MMC3_DAT2, (M4 | PIN_INPUT | VIRTUAL_MODE7) },        /* mmc3_dat2.vin2b_d3 */
        { MMC3_DAT3, (M4 | PIN_INPUT | VIRTUAL_MODE7) },        /* mmc3_dat3.vin2b_d2 */
        { MMC3_DAT4, (M4 | PIN_INPUT | VIRTUAL_MODE7) },        /* mmc3_dat4.vin2b_d1 */
        { MMC3_DAT5, (M4 | PIN_INPUT | VIRTUAL_MODE7) },        /* mmc3_dat5.vin2b_d0 */
        { MMC3_DAT7, (M4 | PIN_INPUT | VIRTUAL_MODE7) },        /* mmc3_dat7.vin2b_clk1 */

	/* alternate mdio */
	{ VIN2A_D10, (M3 | PIN_INPUT_PULLUP) },	/* vin2a_d10.mdio_mclk */
	{ VIN2A_D11, (M3 | PIN_INPUT_PULLUP) },	/* vin2a_d11.mdio_d */
#endif
};

const struct iodelay_cfg_entry dra72_iodelay_cfg_array_revb[] = {
	{ 0x06F0,   359,     0 },	/* CFG_RGMII0_RXC_IN : RGMII0_RXC - GMAC_RGMII0_MANUAL2 */
	{ 0x06FC,   129,  1896 },	/* CFG_RGMII0_RXCTL_IN : RGMII0_RXCTL - GMAC_RGMII0_MANUAL2 */
	{ 0x0708,    80,  1391 },	/* CFG_RGMII0_RXD0_IN : RGMII0_RXD0 - GMAC_RGMII0_MANUAL2 */
	{ 0x0714,   196,  1522 },	/* CFG_RGMII0_RXD1_IN : RGMII0_RXD1 - GMAC_RGMII0_MANUAL2 */
	{ 0x0720,    40,  1860 },	/* CFG_RGMII0_RXD2_IN : RGMII0_RXD2 - GMAC_RGMII0_MANUAL2 */
	{ 0x072C,     0,  1956 },	/* CFG_RGMII0_RXD3_IN : RGMII0_RXD3 - GMAC_RGMII0_MANUAL2 */
	{ 0x0740,     0,   220 },	/* CFG_RGMII0_TXC_OUT : RGMII0_TXC - GMAC_RGMII0_MANUAL2 */
	{ 0x074C,  1820,   180 },	/* CFG_RGMII0_TXCTL_OUT : RGMII0_TXCTL - GMAC_RGMII0_MANUAL2 */
	{ 0x0758,  1740,   440 },	/* CFG_RGMII0_TXD0_OUT : RGMII0_TXD0 - GMAC_RGMII0_MANUAL2 */
	{ 0x0764,  1740,   240 },	/* CFG_RGMII0_TXD1_OUT : RGMII0_TXD1 - GMAC_RGMII0_MANUAL2 */
	{ 0x0770,  1680,   380 },	/* CFG_RGMII0_TXD2_OUT : RGMII0_TXD2 - GMAC_RGMII0_MANUAL2 */
	{ 0x077C,  1740,   440 },	/* CFG_RGMII0_TXD3_OUT : RGMII0_TXD3 - GMAC_RGMII0_MANUAL2 */
	{ 0x0A70,     0,   200 },	/* CFG_VIN2A_D12_OUT : RGMII1_TXC - GMAC_RGMII1_MANUAL2 */
	{ 0x0A7C,  1560,   140 },	/* CFG_VIN2A_D13_OUT : RGMII1_TXCTL - GMAC_RGMII1_MANUAL2 */
	{ 0x0A88,  1700,     0 },	/* CFG_VIN2A_D14_OUT : RGMII1_TXD3 - GMAC_RGMII1_MANUAL2 */
	{ 0x0A94,  1260,     0 },	/* CFG_VIN2A_D15_OUT : RGMII1_TXD2 - GMAC_RGMII1_MANUAL2 */
	{ 0x0AA0,  1400,     0 },	/* CFG_VIN2A_D16_OUT : RGMII1_TXD1 - GMAC_RGMII1_MANUAL2 */
	{ 0x0AAC,  1290,     0 },	/* CFG_VIN2A_D17_OUT : RGMII1_TXD0 - GMAC_RGMII1_MANUAL2 */
	{ 0x0AB0,   596,     0 },	/* CFG_VIN2A_D18_IN : RGMII1_RXC - GMAC_RGMII1_MANUAL2 */
	{ 0x0ABC,   314,   980 },	/* CFG_VIN2A_D19_IN : RGMII1_RXCTL - GMAC_RGMII1_MANUAL2 */
	{ 0x0AD4,   241,  1536 },	/* CFG_VIN2A_D20_IN : RGMII1_RXD3 - GMAC_RGMII1_MANUAL2 */
	{ 0x0AE0,   103,  1689 },	/* CFG_VIN2A_D21_IN : RGMII1_RXD2 - GMAC_RGMII1_MANUAL2 */
	{ 0x0AEC,   161,  1563 },	/* CFG_VIN2A_D22_IN : RGMII1_RXD1 - GMAC_RGMII1_MANUAL2 */
	{ 0x0AF8,     0,  1613 },	/* CFG_VIN2A_D23_IN : RGMII1_RXD0 - GMAC_RGMII1_MANUAL2 */
	{0x144, 0, 0},			/* CFG_GPMC_A13_IN */
	{0x150, 2062, 2277},		/* CFG_GPMC_A14_IN */
	{0x15C, 1960, 2289},		/* CFG_GPMC_A15_IN */
	{0x168, 2058, 2386},		/* CFG_GPMC_A16_IN */
	{0x170, 0, 0 },			/* CFG_GPMC_A16_OUT */
	{0x174, 2062, 2350},		/* CFG_GPMC_A17_IN */
	{0x188, 0, 0},			/* CFG_GPMC_A18_OUT */
	{0x374, 121, 0},		/* CFG_GPMC_CS2_OUT */
	DRA72x_MMC2_DELAY_CONF_ES10
};

const struct iodelay_cfg_entry dra72_iodelay_cfg_array_revc[] = {
	{0x0144, 0, 0},	/* CFG_GPMC_A13_IN */
	{0x0150, 2247, 1186},	/* CFG_GPMC_A14_IN */
	{0x015C, 2176, 1197},	/* CFG_GPMC_A15_IN */
	{0x0168, 2229, 1268},	/* CFG_GPMC_A16_IN */
	{0x0170, 0, 0},	/* CFG_GPMC_A16_OUT */
	{0x0174, 2251, 1217},	/* CFG_GPMC_A17_IN */
	{0x0188, 0, 0},	/* CFG_GPMC_A18_OUT */
	{0x0374, 0, 0},	/* CFG_GPMC_CS2_OUT */
	DRA72x_MMC2_DELAY_CONF_ES10
};

const struct iodelay_cfg_entry dra71_iodelay_cfg_array[] = {
	{0x0144, 0, 0},	/* CFG_GPMC_A13_IN */
	{0x0150, 2247, 1186},	/* CFG_GPMC_A14_IN */
	{0x015C, 2176, 1197},	/* CFG_GPMC_A15_IN */
	{0x0168, 2229, 1268},	/* CFG_GPMC_A16_IN */
	{0x0170, 0, 0},	/* CFG_GPMC_A16_OUT */
	{0x0174, 2251, 1217},	/* CFG_GPMC_A17_IN */
	{0x0188, 0, 0},	/* CFG_GPMC_A18_OUT */
	{0x0374, 0, 0},	/* CFG_GPMC_CS2_OUT */
	{0x06F0, 413, 0},	/* CFG_RGMII0_RXC_IN */
	{0x06FC, 27, 2296},	/* CFG_RGMII0_RXCTL_IN */
	{0x0708, 3, 1721},	/* CFG_RGMII0_RXD0_IN */
	{0x0714, 134, 1786},	/* CFG_RGMII0_RXD1_IN */
	{0x0720, 40, 1966},	/* CFG_RGMII0_RXD2_IN */
	{0x072C, 0, 2057},	/* CFG_RGMII0_RXD3_IN */
	{0x0740, 0, 60},	/* CFG_RGMII0_TXC_OUT */
	{0x074C, 0, 60},	/* CFG_RGMII0_TXCTL_OUT */
	{0x0758, 0, 60},	/* CFG_RGMII0_TXD0_OUT */
	{0x0764, 0, 0},	/* CFG_RGMII0_TXD1_OUT */
	{0x0770, 0, 60},	/* CFG_RGMII0_TXD2_OUT */
	{0x077C, 0, 120},	/* CFG_RGMII0_TXD3_OUT */
	{0x0A38, 0, 0},	/* CFG_VIN2A_CLK0_IN */
	{0x0A44, 1936, 0},	/* CFG_VIN2A_D0_IN */
	{0x0A50, 2031, 0},	/* CFG_VIN2A_D10_IN */
	{0x0A5C, 1702, 0},	/* CFG_VIN2A_D11_IN */
	{0x0A70, 0, 0},	/* CFG_VIN2A_D12_OUT */
	{0x0A7C, 170, 0},	/* CFG_VIN2A_D13_OUT */
	{0x0A88, 150, 0},	/* CFG_VIN2A_D14_OUT */
	{0x0A94, 0, 0},	/* CFG_VIN2A_D15_OUT */
	{0x0AA0, 60, 0},	/* CFG_VIN2A_D16_OUT */
	{0x0AAC, 60, 0},	/* CFG_VIN2A_D17_OUT */
	{0x0AB0, 530, 0},	/* CFG_VIN2A_D18_IN */
	{0x0ABC, 71, 1099},	/* CFG_VIN2A_D19_IN */
	{0x0AC8, 2229, 10},	/* CFG_VIN2A_D1_IN */
	{0x0AD4, 142, 1337},	/* CFG_VIN2A_D20_IN */
	{0x0AE0, 114, 1517},	/* CFG_VIN2A_D21_IN */
	{0x0AEC, 171, 1331},	/* CFG_VIN2A_D22_IN */
	{0x0AF8, 0, 1328},	/* CFG_VIN2A_D23_IN */
	{0x0B04, 1736, 0},	/* CFG_VIN2A_D2_IN */
	{0x0B10, 1943, 0},	/* CFG_VIN2A_D3_IN */
	{0x0B1C, 1601, 0},	/* CFG_VIN2A_D4_IN */
	{0x0B28, 2052, 0},	/* CFG_VIN2A_D5_IN */
	{0x0B34, 1571, 0},	/* CFG_VIN2A_D6_IN */
	{0x0B40, 1855, 0},	/* CFG_VIN2A_D7_IN */
	{0x0B4C, 1224, 618},	/* CFG_VIN2A_D8_IN */
	{0x0B58, 1373, 509},	/* CFG_VIN2A_D9_IN */
	{0x0B7C, 1943, 0},	/* CFG_VIN2A_HSYNC0_IN */
	{0x0B88, 1612, 0},	/* CFG_VIN2A_VSYNC0_IN */
};
#endif

#endif /* _MUX_DATA_DRA7XX_H_ */
