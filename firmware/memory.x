/* Flash offsets are relative to the RP2350 XIP base, 0x10000000. */
MEMORY
{
  FLASH : ORIGIN = 0x10000000, LENGTH = 0x100000
  RAM   : ORIGIN = 0x20000000, LENGTH = 0x82000
}

/* Reserve the first 512 bytes for vectors and the RP2350 image definition. */
_stext = ORIGIN(FLASH) + 0x200;

/* Half-open state partitions; neither is available to the firmware linker. */
__state_start = 0x10100000;
__pool_regions_start = 0x10104000;
__state_end = 0x10308000;
