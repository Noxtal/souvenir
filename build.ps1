go build -o souvenir/
$Env:GOOS+='linux'
$Env:GOARCH+='amd64'
go build -o souvenir/
$Env:GOOS=''
$Env:GOARCH=''
Copy-Item -Path static/ -Destination souvenir/ -Recurse	
Copy-Item -Path templates/ -Destination souvenir/ -Recurse
Compress-Archive -Path souvenir/ -DestinationPath souvenir.zip -Update
Remove-Item souvenir/ -Recurse