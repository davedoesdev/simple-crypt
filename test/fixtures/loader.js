function require(m)
{
    switch (m)
    {
        case 'frame-stream':
            return node_frame_stream;

        case 'stream':
            return node_stream;

		case 'crypto':
			return node_crypto;

        case 'buffer':
            return node_buffer;

        case 'buffer-equal-constant-time':
            return node_buffer_equal_constant_time;

        default:
            throw new Error('module not found: ' + m);
    }
}
