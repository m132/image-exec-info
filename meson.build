# SPDX-License-Identifier: LGPL-2.1-or-later
project('image-exec-info', 'c')

targets = {
    'image-exec-info': ['src/image_exec_info.c', 'src/signature_list.c']
}

efi_incdir = get_option('efi-includedir')
efi_libdir = get_option('efi-libdir')

cc = meson.get_compiler('c')
ld = find_program(cc.get_linker_id())
objcopy = find_program('objcopy')
test = find_program('test')

efi_arch = get_option('efi-arch')
if efi_arch == ''
    efi_arch = host_machine.cpu_family()
endif

if efi_arch == 'x86'
    EFI_MACHINE_TYPE_NAME = 'ia32'
    gnu_efi_arch = 'ia32'
elif efi_arch == 'x86_64'
    EFI_MACHINE_TYPE_NAME = 'x64'
    gnu_efi_arch = 'x86_64'
elif efi_arch == 'arm'
    EFI_MACHINE_TYPE_NAME = 'arm'
    gnu_efi_arch = 'arm'
elif efi_arch == 'aarch64'
    EFI_MACHINE_TYPE_NAME = 'aa64'
    gnu_efi_arch = 'aarch64'
elif efi_arch == 'riscv64'
    EFI_MACHINE_TYPE_NAME = 'riscv64'
    gnu_efi_arch = 'riscv64'
else
    error('Unsupported architecture ' + efi_arch)
endif

gnu_efi_path_arch = ''
foreach name : [gnu_efi_arch, EFI_MACHINE_TYPE_NAME]
    if (gnu_efi_path_arch == '' and name != '' and
        cc.has_header('@0@/@1@/efibind.h'.format(efi_incdir, name)))
            gnu_efi_path_arch = name
    endif
endforeach

if gnu_efi_path_arch == ''
    error('gnu-efi is required, but its headers were not found')
endif

if efi_libdir == ''
    # New location first introduced with gnu-efi 3.0.11
    efi_libdir = '/usr/lib/gnuefi' / EFI_MACHINE_TYPE_NAME
    cmd = run_command(test, '-e', efi_libdir)

    if cmd.returncode() != 0
        # Fall back to the old approach
        cmd = run_command(cc.cmd_array() + ['-print-multi-os-directory'])
        if cmd.returncode() == 0
            path = '/usr/lib' / cmd.stdout().strip()
            cmd = run_command('env', 'realpath', '-e', path)
            if cmd.returncode() == 0
                efi_libdir = cmd.stdout().strip()
            endif
        endif
    endif
endif

libefi = cc.find_library('efi', dirs : efi_libdir, static : true)
libgnuefi = cc.find_library('gnuefi', dirs : efi_libdir, static : true)

efi_location_map = [
    # New locations first introduced with gnu-efi 3.0.11
    [efi_libdir / 'efi.lds',
     efi_libdir / 'crt0.o'],
    # Older locations...
    [efi_libdir / 'gnuefi' / 'elf_@0@_efi.lds'.format(gnu_efi_path_arch),
     efi_libdir / 'gnuefi' / 'crt0-efi-@0@.o'.format(gnu_efi_path_arch)],
    [efi_libdir / 'elf_@0@_efi.lds'.format(gnu_efi_path_arch),
     efi_libdir / 'crt0-efi-@0@.o'.format(gnu_efi_path_arch)]]
efi_lds = ''
foreach location : efi_location_map
    if efi_lds == ''
        cmd = run_command(test, '-f', location[0])
        if cmd.returncode() == 0
            efi_lds = location[0]
            efi_crt0 = location[1]
        endif
    endif
endforeach
if efi_lds == ''
    error('gnu-efi is required, but its CRT and linking script were not found')
endif

efi_compile_args = cc.get_supported_arguments([
    '-ffreestanding',
    '-fno-stack-protector',
    '-fno-strict-aliasing',
    '-fshort-wchar',
]) + [
    '-nostdlib',
    '-std=gnu99'
]
if efi_arch == 'x86_64'
    efi_compile_args += [
        '-mno-red-zone',
        '-mno-sse',
        '-mno-mmx',
        '-DEFI_FUNCTION_WRAPPER',
        '-DGNU_EFI_USE_MS_ABI'
    ]
elif efi_arch == 'ia32'
    efi_compile_args += ['-mno-sse', '-mno-mmx']
elif efi_arch == 'arm'
    efi_compile_args += cc.get_supported_arguments([
        '-mgeneral-regs-only',
        '-mfpu=none'
    ])
endif

efi_ldflags = [
    '-Wl,-T' + efi_lds, # for some reason, this has to be prefixed with -Wl
    '-Wl,-Bsymbolic',
    '-nostdlib',
    '-znocombreloc',
    efi_crt0
]
if ['aarch64', 'arm', 'riscv64'].contains(efi_arch)
    # Aarch64, ARM32 and 64bit RISC-V don't have an EFI capable objcopy.
    # Use 'binary' instead, and add required symbols manually.
    efi_ldflags += ['-Wl,--defsym=EFI_SUBSYSTEM=0xa']
    efi_format = ['-O', 'binary']
else
    efi_format = ['--target=efi-app-@0@'.format(gnu_efi_arch)]
endif

gnuefi = declare_dependency(
    compile_args : efi_compile_args,
    dependencies : [libefi, libgnuefi],
    include_directories : [efi_incdir, efi_incdir / gnu_efi_path_arch],
    link_args : efi_ldflags
)

foreach name, sources : targets
    so = shared_library(name,
        sources,
        build_by_default : false,
        dependencies : gnuefi
    )
    app = custom_target(name + '.efi',
        build_by_default : true,
        input : so,
        output : name + '.efi',
        command : [objcopy,
                '-j', '.text',
                '-j', '.sdata',
                '-j', '.sbat',
                '-j', '.data',
                '-j', '.dynamic',
                '-j', '.dynsym',
                '-j', '.rel*',
                efi_format,
                '@INPUT@', '@OUTPUT@']
    )
endforeach
