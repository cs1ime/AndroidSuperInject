import sys

filename = sys.argv[1]

with open(filename,'rb') as sf:
    data=sf.read()


c_array = ['0x{:02X}'.format(byte) for byte in data]
c_array_str = ', '.join(c_array)

namespace = 'binso'

header_content = '#ifndef _BINARY_DATA_H_\n'
header_content += '#define _BINARY_DATA_H_\n\n'
header_content += 'namespace ' + namespace + ' {\n\n'
header_content += 'unsigned char binary_data[] = {\n'
header_content += '   ' + c_array_str + '\n};\n\n'
header_content += '}\n\n'
header_content += '#endif'

print(header_content)
