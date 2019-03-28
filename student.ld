SECTIONS {
    . = 0x3000;
    .text : { *(.text) }

    /* 256-byte guard against geniuses */
    . += 0x100;
    .data : { *(.data) }
    .bss : { *(.bss) }
}
