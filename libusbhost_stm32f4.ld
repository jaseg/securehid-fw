/*
 * This file is part of the libopencm3 project.
 *
 * Copyright (C) 2009 Uwe Hermann <uwe@hermann-uwe.de>
 * Copyright (C) 2011 Stephen Caudle <scaudle@doceme.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Minimal linker script for chinese STM32F4 board (STM32F407VE, 512K flash, 128K RAM). */

/* Define memory regions. */
MEMORY
{
	rom (rx) : ORIGIN = 0x08000000, LENGTH = 512K
	ram (rwx) : ORIGIN = 0x20000000, LENGTH = 112K /* Main SRAM */
	sram2 (rwx) : ORIGIN = 0x2001c000, LENGTH = 16K /* SRAM2 with some security features (?) */
	ccm (rwx) : ORIGIN = 0x10000000, LENGTH = 64K /* Fast core-coupled memory */
	backup (rwx) : ORIGIN = 0x40024000, LENGTH = 4K /* Battery-backed backup SRAM */
}

/* Include the common ld script. */
INCLUDE libopencm3_stm32f4.ld

