rm source.zip
cd source
zip -r ../source.zip . -x '*.git*' -x '*cdk.out*' -x '*.vscode*'