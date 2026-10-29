/* RP2350 Boot ROM scans the first 4 KiB for the image definition block. */
ASSERT(ADDR(.start_block) + SIZEOF(.start_block) <= _stext, "RP2350 image definition exceeds reserved boot area");
SECTIONS
{
  .start_block : ALIGN(4)
  {
    KEEP(*(.start_block));
  } > FLASH
}

INSERT AFTER .vector_table;
