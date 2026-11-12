wkfido: wkfido.m wkfido.entitlements
	clang -fobjc-arc -Wno-objc-protocol-method-implementation -framework Foundation -framework WebKit -framework CryptoTokenKit -o wkfido wkfido.m
	codesign -f -s - --entitlements wkfido.entitlements wkfido
