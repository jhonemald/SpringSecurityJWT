package org.ada.school.user.config;

import org.ada.school.user.error.InternalServerErrorException;
import org.ada.school.user.exception.ServerErrorResponseDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

@RestControllerAdvice
class RestControllerErrorHandler
{

    @ExceptionHandler( HttpMessageNotReadableException.class )
    private ResponseEntity<String> handleHTTPMessageNotReadable( HttpMessageNotReadableException exception )
    {
        return new ResponseEntity<>( exception.getCause().getMessage(), HttpStatus.BAD_REQUEST );
    }

    @ExceptionHandler( MissingServletRequestPartException.class )
    private ResponseEntity<String> handleMissingServletRequestPart( MissingServletRequestPartException exception )

    {
        return new ResponseEntity<>( exception.getCause().getMessage(), HttpStatus.BAD_REQUEST );
    }

    @ExceptionHandler( InternalServerErrorException.class )
    private ResponseEntity<ServerErrorResponseDto> handleRuntimeException( InternalServerErrorException exception )

    {
        return new ResponseEntity<>( exception.getServerErrorResponseDto(), exception.getHttpStatus() );
    }
}
