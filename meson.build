project('silverware', 'cpp',
  version: '0.0.1',
  default_options: ['warning_level=3', 'cpp_std=c++14'])

add_global_arguments('-Wno-gnu-zero-variadic-macro-arguments', language: 'cpp')

subdir('_user')

silver = shared_library('silver',
    files('src/forklift.cpp'),
    include_directories: ['include', 'src'],
    link_args: ['-lkernel32', '-ladvapi32', '-lntdll'],
    install: true
  )

executable('test-silverware',
    files('samples/forktest.cpp'),
    include_directories: ['include', 'src'], # dbg.h is nonpublic
    link_with: [silver],
    install: true
  )
