
require 'rspec'
require_relative 'scrambled_egg'

#

describe "ScrambledEgg" do

  context "Create Egg" do
    egg = ScrambledEgg.new

    it "Should test all default pre, enc, post" do
      # Scramble cycle
      for pre, _ in SCRAMBLE do
        # Encryption cycle
        for enc, _ in ENC do
          # Encode
          for post, _ in ENCODE do
            text = (0..500).map{ ('0'..'z').to_a[rand(75)] }.join
            pwd = (0..100).map{ ('0'..'z').to_a[rand(75)] }.join
            encrypted = egg.encrypt(text, pre, enc, post, pwd)
            #decrypted =
          end
        end
      end
    end

  end
end
