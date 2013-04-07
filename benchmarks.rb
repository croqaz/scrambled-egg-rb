
require "benchmark"
require "openssl"

nr = 100_000
str = "Some long and ugly string :)"

# Testing HEX encoding
time = Benchmark.measure do
    (1..nr).each { s = str.unpack('H*') ; s.pack('H*') }
end
puts "Hex encoding took:"
puts time

# Testing Hexdigest
time = Benchmark.measure do
    (1..nr).each { s = Digest.hexencode(str) ; [s].pack('H*') }
end
puts "Hexdigest took:"
puts time

# Testing scan and join HEX
time = Benchmark.measure do
    (1..nr).each { s = Digest.hexencode(str) ; s.scan( /../ ).map { |x| x.hex.chr }.join }
end
puts "Scan and join HEX took:"
puts time

#

# Testing str Base64 encoding
time = Benchmark.measure do
    (1..nr).each { s = [str].pack('m') ; s.unpack('m') }
end
puts "Base64 std encoding took:"
puts time

# Testing strict Base64 encoding
time = Benchmark.measure do
    (1..nr).each { s = [str].pack('m0') ; s.unpack('m0') }
end
puts "Base64 strict encoding took:"
puts time
