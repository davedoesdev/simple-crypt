function require(m)
{
    switch (m)
    {
        case 'frame-stream':
            return node_frame_stream;

        case 'stream':
            return node_stream;

        case 'buffer':
            return node_buffer;

        default:
            throw new Error('module not found: ' + m);
    }
}
