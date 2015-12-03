// Copyright 2011 INDILINX Co., Ltd.
//
// This file is part of Jasmine.
//
// Jasmine is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Jasmine is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Jasmine. See the file COPYING.
// If not, see <http://www.gnu.org/licenses/>.


#include "jasmine.h"
// TODO to delete after the implementation of bloc map addresing
#define PAGE_MAP_ADDR BLK_MAP_ADDR
#define PAGE_MAP_BYTES BLK_MAP_BYTES
#define VC_MAX              0xCDCD// means that bloc i is invalid (bad block )


//----------------------------------
// metadata structure
//----------------------------------

typedef struct _physical_addr
{
	UINT32 blk;
	UINT32 page;
}physical_addr;


static void sanity_check(void);
static BOOL32 is_bad_block(UINT32 const bank, UINT32 const vblk_offset);
static UINT32 get_physical_address(UINT32 const lpage_addr);
static void update_physical_address(UINT32 const lpage_addr, UINT32 const new_bank, UINT32 const new_row);

static UINT32 get_free_page(UINT32 const bank);
static BOOL32 check_format_mark(void);
static void write_format_mark(void);
static void format(void);

UINT32 g_ftl_read_buf_id;
UINT32 g_ftl_write_buf_id;
static UINT32 g_target_row[NUM_BANKS];
static UINT32 g_target_bank;

static volatile UINT32 g_read_fail_count;
static volatile UINT32 g_program_fail_count;
static volatile UINT32 g_erase_fail_count;

static UINT32 g_scan_list_entries[NUM_BANKS];
//************************ usefull macros ************************//
#define get_num_bank(lpn)             ((lpn) / PAGES_PER_BANK)


//*************************   my vars ****************************//

static UINT32 log_offset ;


//************************* Myfunctions *************************//
void showlogs();
static int is_in_log(UINT32 const lpage_addr);  //  < 0 if it doesent' exist
static physical_addr get_physical_data_addr(UINT32 const lpage_addr);
static BOOL32 check_if_exist(UINT32 lpage_addr);

//***************************************************************//



//************************* Myfunctions *************************//
static int is_in_log(UINT32 const lpage_addr)  // if the page existe in the log block  i >0
{int i;
   for (i = log_offset ; i >= 0 ; i--)
   {
	   if(read_dram_32(LOG_MAP_ADDR+sizeof(UINT32) * i) == lpage_addr )
		   break;
   }

   return i ;
}

static physical_addr get_physical_data_addr(UINT32 const lpage_addr)
{
	physical_addr p_addr;
	int offset = is_in_log(lpage_addr) ;

	if ( offset >= 0 ) // the page exist in log blocks
	{   int blk = offset / PAGES_PER_BLK ;
		p_addr.page = offset;
		p_addr.blk  = read_dram_32(LOG_BLKS_MAP_ADDR+sizeof(UINT32) * blk);
	}
	else // the page exist in data block
	{
		UINT32 blk = lpage_addr / PAGES_PER_BLK ;
		p_addr.page= lpage_addr % PAGES_PER_BLK ;
		p_addr.blk = read_dram_32(BLK_MAP_ADDR + sizeof(UINT32)*blk);
	}


	return p_addr;
}


static BOOL32 check_if_exist(UINT32 lpage_addr)
{
	UINT32 blk = lpage_addr / PAGES_PER_BLK ;
	return read_dram_32(BLK_MAP_ADDR + sizeof(UINT32)*blk) != NULL ;
}

//***************************************************************//





void ftl_open(void)
{
	sanity_check();
	showlogs();
	// STEP 1 - read scan lists from NAND flash

	scan_list_t* scan_list = (scan_list_t*) SCAN_LIST_ADDR;
	UINT32 bank;

	// Since we are going to check the flash interrupt flags within this function, ftl_isr() should not be called.
	disable_irq();

	flash_clear_irq();	// clear any flash interrupt flags that might have been set

	for (bank = 0; bank < NUM_BANKS; bank++)
	{
		SETREG(FCP_CMD, FC_COL_ROW_READ_OUT);			// FC_COL_ROW_READ_OUT = sensing and data output
		SETREG(FCP_OPTION, FO_E);						// scan list was written in 1-plane mode by install.exe, so there is no FO_P
		SETREG(FCP_DMA_ADDR, scan_list + bank);			// target address should be DRAM or SRAM (see flash.h for rules)
		SETREG(FCP_DMA_CNT, SCAN_LIST_SIZE);			// number of bytes for data output
		SETREG(FCP_COL, 0);
		SETREG(FCP_ROW_L(bank), SCAN_LIST_PAGE_OFFSET);	// scan list was written to this position by install.exe
		SETREG(FCP_ROW_H(bank), SCAN_LIST_PAGE_OFFSET);	// Tutorial FTL always uses the same row addresses for high chip and low chip

		flash_issue_cmd(bank, RETURN_ON_ISSUE);			// Take a look at the source code of flash_issue_cmd() now.
	}

	// This while() statement waits the last issued command to be accepted.
	// If bit #0 of WR_STAT is one, a flash command is in the Waiting Room, because the target bank has not accepted it yet.
	while ((GETREG(WR_STAT) & 0x00000001) != 0);

	// Now, FC_COL_ROW_READ_OUT commands are accepted by all the banks.
	// Before checking whether scan lists are corrupted or not, we have to wait the completion of read operations.
	// This code shows how to wait for ALL the banks to become idle.
	while (GETREG(MON_CHABANKIDLE) != 0);

	// Now we can check the flash interrupt flags.

	for (bank = 0; bank < NUM_BANKS; bank++)
	{
		UINT32 num_entries = NULL;
		UINT32 result = OK;

		if (BSP_INTR(bank) & FIRQ_DATA_CORRUPT)
		{
			// Too many bits are corrupted so that they cannot be corrected by ECC.
			result = FAIL;
		}
		else
		{
			// Even though the scan list is not corrupt, we have to check whether its contents make sense.

			UINT32 i;

			num_entries = read_dram_16(&(scan_list[bank].num_entries));

			if (num_entries > SCAN_LIST_ITEMS)
			{
				result = FAIL;	// We cannot trust this scan list. Perhaps a software bug.
			}
			else
			{
				for (i = 0; i < num_entries; i++)
				{
					UINT16 entry = read_dram_16(&(scan_list[bank].list[i]));
					UINT16 pblk_offset = entry & 0x7FFF;

					if (pblk_offset == 0 || pblk_offset >= PBLKS_PER_BANK)
					{
						#if OPTION_REDUCED_CAPACITY == FALSE
						result = FAIL;	// We cannot trust this scan list. Perhaps a software bug.
						#endif
					}
					else
					{
						// Bit position 15 of scan list entry is high-chip/low-chip flag.
						// Remove the flag in order to make is_bad_block() simple.

						write_dram_16(&(scan_list[bank].list[i]), pblk_offset);
					}
				}
			}
		}

		if (result == FAIL)
		{
			mem_set_dram(scan_list + bank, 0, SCAN_LIST_SIZE);
			g_scan_list_entries[bank] = 0;
		}
		else
		{
			write_dram_16(&(scan_list[bank].num_entries), 0);
			g_scan_list_entries[bank] = num_entries;
		}
	}

	// STEP 2 - If necessary, do low-level format
	// format() should be called after loading scan lists, because format() calls is_bad_block().

	if (check_format_mark() == FALSE)
	{
		// When ftl_open() is called for the first time (i.e. the SSD is powered up the first time)
		// format() is called.

		format();
	}

	// STEP 3 - initialize page mapping table
	// The page mapping table is too large to fit in SRAM.
	mem_set_dram(BLK_MAP_ADDR,NULL,BLK_MAP_BYTES);
	mem_set_dram(PAGE_MAP_ADDR,NULL,PAGE_MAP_BYTES);
	mem_set_dram(PAGE_MAP_ADDR, NULL, PAGE_MAP_BYTES);

	// STEP 4 - initialize global variables that belong to FTL

	g_ftl_read_buf_id = 0;
	g_ftl_write_buf_id = 0;
	g_target_bank = 0;

	for (bank = 0; bank < NUM_BANKS; bank++)
	{
		g_target_row[bank] = PAGES_PER_VBLK;
	}

	flash_clear_irq();

	// This example FTL can handle runtime bad block interrupts and read fail (uncorrectable bit errors) interrupts

	SETREG(INTR_MASK, FIRQ_DATA_CORRUPT | FIRQ_BADBLK_L | FIRQ_BADBLK_H);
	SETREG(FCONF_PAUSE, FIRQ_DATA_CORRUPT | FIRQ_BADBLK_L | FIRQ_BADBLK_H);

	enable_irq();
}






void ftl_read(UINT32 const lba, UINT32 const total_sectors)
{
	UINT32 bank, row, num_sectors_to_read, temp;
	UINT32 lpage_addr		= lba / SECTORS_PER_PAGE;	// logical page address
	UINT32 sect_offset 		= lba % SECTORS_PER_PAGE;	// sector offset within the page
	UINT32 sectors_remain	= total_sectors;

	physical_addr p_addr ;




	while (sectors_remain != 0)	// one page per iteration
	{
		if (sect_offset + sectors_remain < SECTORS_PER_PAGE) // sect_offset ==0 or
		{
			num_sectors_to_read = sectors_remain;
		}
		else
		{
			num_sectors_to_read = SECTORS_PER_PAGE - sect_offset;
		}

		p_addr = get_physical_data_addr(lpage_addr);
		temp = p_addr.blk;

		if (p_addr.blk != NULL)
		{
			nand_page_ptread_to_host(bank,
															 p_addr.blk,
															 p_addr.page,
															 sect_offset,
															 num_sectors_to_read);
		}
		else // i really hate this party -_-"
		{
			UINT32 next_read_buf_id = (g_ftl_read_buf_id + 1) % NUM_RD_BUFFERS;

			#if OPTION_FTL_TEST == 0
			while (next_read_buf_id == GETREG(SATA_RBUF_PTR));	// wait if the read buffer is full (slow host)
			#endif

            // fix bug @ v.1.0.6
            // Send 0xFF...FF to host when the host request to read the sector that has never been written.
            // In old version, for example, if the host request to read unwritten sector 0 after programming in sector 1, Jasmine would send 0x00...00 to host.
            // However, if the host already wrote to sector 1, Jasmine would send 0xFF...FF to host when host request to read sector 0. (ftl_read() in ftl_xxx/ftl.c)
			mem_set_dram(RD_BUF_PTR(g_ftl_read_buf_id) + sect_offset*BYTES_PER_SECTOR,
                         0xFFFFFFFF, num_sectors_to_read*BYTES_PER_SECTOR);

            flash_finish();

			SETREG(BM_STACK_RDSET, next_read_buf_id);	// change bm_read_limit
			SETREG(BM_STACK_RESET, 0x02);				// change bm_read_limit

			g_ftl_read_buf_id = next_read_buf_id;

		}

		sect_offset = 0;
		sectors_remain -= num_sectors_to_read;
		lpage_addr++;
	}
}

void ftl_write(UINT32 const lba, UINT32 const total_sectors)
{
	uart_printf("lba %d \n total secotrs %d",lba,total_sectors);
	UINT32 remain_sects, num_sectors_to_write;
	UINT32 lpn, sect_offset;

	lpn          = lba / SECTORS_PER_PAGE;
	sect_offset  = lba % SECTORS_PER_PAGE;
	remain_sects = num_sectors;

	while (remain_sects != 0)
	{
			if ((sect_offset + remain_sects) < SECTORS_PER_PAGE)
			{
					num_sectors_to_write = remain_sects;
			}
			else
			{
					num_sectors_to_write = SECTORS_PER_PAGE - sect_offset;
			}
			// single page write individually
			write_page(lpn, sect_offset, num_sectors_to_write);

			sect_offset   = 0;
			remain_sects -= num_sectors_to_write;
			lpn++;
	}
}

static void write_page(UINT32 const lpn, UINT32 const sect_offset, UINT32 const num_sectors)
{

}

void ftl_flush(void)
{
	// do nothing
}

static BOOL32 is_bad_block(UINT32 const bank, UINT32 const vblk_offset)
{
	// The scan list, which is installed by installer.c:install_block_zero(), contains physical block offsets of initial bad blocks.
	// Since the parameter to is_bad_block() is not a pblk_offset but a vblk_offset, we have to do some conversion.
	//
	// When 1-plane mode is used, vblk_offset is equivalent to pblk_offset.
	// When 2-plane mode is used, vblk_offset = pblk_offset / 2.
	// Two physical blocks 0 and 1 are grouped into virtual block 0.
	// Two physical blocks 2 and 3 are grouped into virtual block 1.
	// Two physical blocks 4 and 5 are grouped into virtual block 2.

#if OPTION_2_PLANE

	UINT32 pblk_offset;
	scan_list_t* scan_list = (scan_list_t*) SCAN_LIST_ADDR;

	pblk_offset = vblk_offset * NUM_PLANES;

	if (mem_search_equ_dram(scan_list + bank, sizeof(UINT16), g_scan_list_entries[bank], pblk_offset) < g_scan_list_entries[bank])
	{
		return TRUE;
	}

	pblk_offset = vblk_offset * NUM_PLANES + 1;

	if (mem_search_equ_dram(scan_list + bank, sizeof(UINT16), g_scan_list_entries[bank], pblk_offset) < g_scan_list_entries[bank])
	{
		return TRUE;
	}

	return FALSE;

#else

	scan_list_t* scan_list = (scan_list_t*) SCAN_LIST_ADDR;

	if (mem_search_equ_dram(scan_list + bank, sizeof(UINT16), g_scan_list_entries[bank], vblk_offset) < g_scan_list_entries[bank])
	{
		return TRUE;
	}

	return FALSE;

#endif
}

static UINT32 get_physical_address(UINT32 const lpage_addr)
{
	// Page mapping table entry size is 4 byte.
	return read_dram_32(PAGE_MAP_ADDR + lpage_addr * sizeof(UINT32));
}

static void update_physical_address(UINT32 const lpage_addr, UINT32 const new_bank, UINT32 const new_row)
{
	write_dram_32(PAGE_MAP_ADDR + lpage_addr * sizeof(UINT32), new_bank * PAGES_PER_BANK + new_row);
}

static UINT32 get_free_page(UINT32 const bank)
{
	// This function returns the row address for write operation.

	UINT32 row;
	UINT32 vblk_offset, page_offset;

	row = g_target_row[bank];
	vblk_offset = row / PAGES_PER_VBLK;
	page_offset = row % PAGES_PER_VBLK;

	if (page_offset == 0)	// We are going to write to a new vblock.
	{
		while (is_bad_block(bank, vblk_offset) && vblk_offset < VBLKS_PER_BANK)
		{
			vblk_offset++;	// We have to skip bad vblocks.
		}
	}

	if (vblk_offset >= VBLKS_PER_BANK)
	{
		// Free vblocks are exhausted. Since this example FTL does not do garbage collection,
		// no more data can be written to this SSD. The SSD stops working now.

		led (1);
		while (1);
	}

	row = vblk_offset * PAGES_PER_VBLK + page_offset;

	g_target_row[bank] = row + 1;

	return row;
}

static BOOL32 check_format_mark(void)
{
	// This function reads a flash page from (bank #0, block #0) in order to check whether the SSD is formatted or not.

	#ifdef __GNUC__
	extern UINT32 size_of_firmware_image;
	UINT32 firmware_image_pages = (((UINT32) (&size_of_firmware_image)) + BYTES_PER_FW_PAGE - 1) / BYTES_PER_FW_PAGE;
	#else
	extern UINT32 Image$$ER_CODE$$RO$$Length;
	extern UINT32 Image$$ER_RW$$RW$$Length;
	UINT32 firmware_image_bytes = ((UINT32) &Image$$ER_CODE$$RO$$Length) + ((UINT32) &Image$$ER_RW$$RW$$Length);
	UINT32 firmware_image_pages = (firmware_image_bytes + BYTES_PER_FW_PAGE - 1) / BYTES_PER_FW_PAGE;
	#endif

	UINT32 format_mark_page_offset = FW_PAGE_OFFSET + firmware_image_pages;
	UINT32 temp;

	flash_clear_irq();	// clear any flash interrupt flags that might have been set

	SETREG(FCP_CMD, FC_COL_ROW_READ_OUT);
	SETREG(FCP_BANK, REAL_BANK(0));
	SETREG(FCP_OPTION, FO_E);
	SETREG(FCP_DMA_ADDR, FTL_BUF_ADDR); 	// flash -> DRAM
	SETREG(FCP_DMA_CNT, BYTES_PER_SECTOR);
	SETREG(FCP_COL, 0);
	SETREG(FCP_ROW_L(0), format_mark_page_offset);
	SETREG(FCP_ROW_H(0), format_mark_page_offset);

	// At this point, we do not have to check Waiting Room status before issuing a command,
	// because scan list loading has been completed just before this function is called.
	SETREG(FCP_ISSUE, NULL);

	// wait for the FC_COL_ROW_READ_OUT command to be accepted by bank #0
	while ((GETREG(WR_STAT) & 0x00000001) != 0);

	// wait until bank #0 finishes the read operation
	while (BSP_FSM(0) != BANK_IDLE);

	// Now that the read operation is complete, we can check interrupt flags.
	temp = BSP_INTR(0) & FIRQ_ALL_FF;

	// clear interrupt flags
	CLR_BSP_INTR(0, 0xFF);

	if (temp != 0)
	{
		return FALSE;	// the page contains all-0xFF (the format mark does not exist.)
	}
	else
	{
		return TRUE;	// the page contains something other than 0xFF (it must be the format mark)
	}
}

static void write_format_mark(void)
{
	// This function writes a format mark to a page at (bank #0, block #0).

	#ifdef __GNUC__
	extern UINT32 size_of_firmware_image;
	UINT32 firmware_image_pages = (((UINT32) (&size_of_firmware_image)) + BYTES_PER_FW_PAGE - 1) / BYTES_PER_FW_PAGE;
	#else
	extern UINT32 Image$$ER_CODE$$RO$$Length;
	extern UINT32 Image$$ER_RW$$RW$$Length;
	UINT32 firmware_image_bytes = ((UINT32) &Image$$ER_CODE$$RO$$Length) + ((UINT32) &Image$$ER_RW$$RW$$Length);
	UINT32 firmware_image_pages = (firmware_image_bytes + BYTES_PER_FW_PAGE - 1) / BYTES_PER_FW_PAGE;
	#endif

	UINT32 format_mark_page_offset = FW_PAGE_OFFSET + firmware_image_pages;

	mem_set_dram(FTL_BUF_ADDR, 0, BYTES_PER_SECTOR);

	SETREG(FCP_CMD, FC_COL_ROW_IN_PROG);
	SETREG(FCP_BANK, REAL_BANK(0));
	SETREG(FCP_OPTION, FO_E | FO_B_W_DRDY);
	SETREG(FCP_DMA_ADDR, FTL_BUF_ADDR); 	// DRAM -> flash
	SETREG(FCP_DMA_CNT, BYTES_PER_SECTOR);
	SETREG(FCP_COL, 0);
	SETREG(FCP_ROW_L(0), format_mark_page_offset);
	SETREG(FCP_ROW_H(0), format_mark_page_offset);

	// At this point, we do not have to check Waiting Room status before issuing a command,
	// because we have waited for all the banks to become idle before returning from format().
	SETREG(FCP_ISSUE, NULL);

	// wait for the FC_COL_ROW_IN_PROG command to be accepted by bank #0
	while ((GETREG(WR_STAT) & 0x00000001) != 0);

	// wait until bank #0 finishes the write operation
	while (BSP_FSM(0) != BANK_IDLE);
}

static void format(void)
{ led(0);
	UINT32 bank, vblock, vcount_val;

	uart_printf("Total FTL DRAM metadata size: %d KB", DRAM_BYTES_OTHER / 1024);

    uart_printf("VBLKS_PER_BANK: %d", VBLKS_PER_BANK);
    uart_printf("LBLKS_PER_BANK: %d", NUM_LPAGES / PAGES_PER_BLK / NUM_BANKS);

	for (bank = 0; bank < NUM_BANKS; bank++)

	{
		for (vblock = 1; vblock < VBLKS_PER_BANK; vblock++)
		{
            vcount_val = VC_MAX;
            if (is_bad_block(bank, vblock) == FALSE)
			{
				nand_block_erase(bank, vblock);
                vcount_val = 0;
            }
            write_dram_16(VCOUNT_ADDR + ((bank * VBLKS_PER_BANK) + vblock) * sizeof(UINT16), vcount_val); // vcount_addr[i] ==0 means that the block i is valid

		}
    }


	#if 0
	write_format_mark();
	#endif

	led(1);
	uart_printf("end format");
}

void ftl_isr(void)
{
    UINT32 bank;
    UINT32 bsp_intr_flag;

    uart_printf("BSP interrupt occured...");
    // interrupt pending clear (ICU)
    SETREG(APB_INT_STS, INTR_FLASH);

    for (bank = 0; bank < NUM_BANKS; bank++) {
        while (BSP_FSM(bank) != BANK_IDLE);
        // get interrupt flag from BSP
        bsp_intr_flag = BSP_INTR(bank);

        if (bsp_intr_flag == 0) {
            continue;
        }
        UINT32 fc = GETREG(BSP_CMD(bank));
        // BSP clear
        CLR_BSP_INTR(bank, bsp_intr_flag);

        // interrupt handling
		if (bsp_intr_flag & FIRQ_DATA_CORRUPT) {
            uart_printf("BSP interrupt at bank: 0x%x", bank);
            uart_printf("FIRQ_DATA_CORRUPT occured...");
		}
		if (bsp_intr_flag & (FIRQ_BADBLK_H | FIRQ_BADBLK_L)) {
            uart_printf("BSP interrupt at bank: 0x%x", bank);
			if (fc == FC_COL_ROW_IN_PROG || fc == FC_IN_PROG || fc == FC_PROG) {
                uart_printf("find runtime bad block when block program...");
			}
			else {
                uart_printf("find runtime bad block when block erase...vblock #: %d", GETREG(BSP_ROW_H(bank)) / PAGES_PER_BLK);
				ASSERT(fc == FC_ERASE);
			}
		}
    }
}

static void sanity_check(void)
{
	UINT32 dram_requirement = RD_BUF_BYTES + WR_BUF_BYTES + COPY_BUF_BYTES + FTL_BUF_BYTES
		+ HIL_BUF_BYTES + TEMP_BUF_BYTES + SCAN_LIST_BYTES + PAGE_MAP_BYTES;

	if (dram_requirement > DRAM_SIZE)
	{
		while (1);
	}
}


/*********************log fcts**************/
void showlogs()
{
	uart_printf("-----------logs--------------");
	uart_printf("NUM_BANKS: %d",NUM_BANKS);
	uart_printf("PAGES PER_BLK: %d",PAGES_PER_BLK);
	uart_printf("total pages: %d , data pages %d",NUM_LPAGES ,NUM_DATA_BLKS *PAGES_PER_BLK);
	uart_printf("NUM_DATA_BLKS: %d",NUM_DATA_BLKS);
	uart_printf("NUM_LOG_BLKs: %d" , NUM_LOG_BLKS);

}
