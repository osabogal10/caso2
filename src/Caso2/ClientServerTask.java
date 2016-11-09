package Caso2;

import java.io.IOException;

import uniandes.gload.core.Task;

public class ClientServerTask extends Task {

	@Override
	public void fail() {
		System.out.println(Task.MENSAJE_FAIL);
	}

	@Override
	public void success() {
		System.out.println(Task.OK_MESSAGE);
	}

	@Override
	public void execute() {
		try {
			Cliente cliente = new Cliente();
		} catch (IOException e) {
			System.out.println("Error al crear cliente");
		}
	}

}
