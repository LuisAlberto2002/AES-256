//Llamamos las librerias que seran necesarias para la ejecucion del algoritmo.
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#pragma intrinsic(__rdtsc)
//Definimos una variable llamada NTEST con un valor fijo de tipo int
#define NTEST 100000
//Creamos una funcion de tipo void que se ejecutara mientras se cumpla que el valor del apuntador var sea =1
void measured_function(volatile int* var) { (*var) = 1; }

/*static const unsigned char key[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};*/
//Iniciamos el algoritmo
int main() {
	//Declaramos las variables de tipo char de nombre: text,enc_out, dec_out y key.
	//Donde text guardara el mensaje a cifrar, y key guardara la llave que se empleara para cifrar
    unsigned char text[] = "This is so much fun!";
    unsigned char enc_out[80];
    unsigned char dec_out[80];

    unsigned char key[32];
    //Declaramos una variable rc de tipo int a la cual se le asignara un valor aleatorio en base a la variable key
    //y su tamano.
    int rc = Rand_bytes(key, sizeof(key));
    //creamos una variable err para indicar cuando un recurso no existe
    unsigned long err = ERR_get_error();
    //Establecemos una condicional en la que  mientras rc sea igual a 1, el codigo continuara ejecutandoce correctamente
    //caso contrario devolvera -1 lo que generara un error.
    if (rc != 1)
        return -1;

    AES_KEY enc_key, dec_key;
    //Declaramos variable variable con valor de 0.
    int variable = 0;
    //Declaramos las variable start,end con un valor entero de 64 bits
    uint64_t start, end;

    printf("Calentamiento...\n");
    for (int i = 0; i < NTEST; i++)
        measured_function(&variable);
    //Empleamos funciones de cifrado aes, para construir la llave para cifrar el mensaje, cifrar el mensaje empleado
    //crear la llave para descifrar el mensaje, y descifrar el mensaje.
    AES_set_encrypt_key(key, 128, &enc_key);

    AES_encrypt(text, enc_out, &enc_key);

    AES_set_decrypt_key(key, 128, &dec_key);
    AES_decrypt(enc_out, dec_out, &dec_key);
    //Mandamos imprimir el mensaje original empleando un ciclo for ya que hablamos de un arreglo de caracteres.
    //Realizaciamos el mismo proceso para imprimir el mensaje cifrado y el mensaje descifrado.
    //Mandamos imprimir el mensaje cifrado para asegurarnos de que el mensaje fue descifrado correctamente.
    printf("original:\t");
    int stop = sizeof(text) - 1;
    for (int i = 0; *(text + i) != 0x00; i++)
        printf("%c ", *(text + i));
    printf("\nencrypted:\t");
    for (int i = 0; *(enc_out + i) != 0x00; i++)
        printf("%.2X ", *(enc_out + i));
    printf("\ndecrypted:\t");
    for (int i = 0; i < 16; i++)
        printf("%c ", *(dec_out + i));
    printf("\n");
}
