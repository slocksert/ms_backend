from fastapi import HTTPException, status

def len_password():
    raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least  10 characters long"
    )

def email_not_valid():
    raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Invalid email format"
    )

def existent_email():
    raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, 
            detail="Existent email"
    )

def no_cnpj():
    raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail='CNPJ is required'
    )

def existent_cnpj():
    raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='Existent CNPJ'
    )

def cpf_len_and_is_digit():
    raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='CNPJ should have exactly 14 digits'
    )

def incorrect_user():
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Incorrect username or password"
    )

def invalid_username():
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid user"
    )


def incorrect_password():
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Incorrect username or password"
    )

def wrong_password():
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Old password not valid"
    )

def jwt_error():
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid access token"
    )

def unauthorized():
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized", 
            headers={"WWW-Authenticate": "Bearer"}
    )

def image_error(e = "Image not sent"):
    raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"An error ocurred while trying to save the image on the database: {e}"
    )

def existent_password():
    raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="New password is equal to current password. Please try a different one."
    )