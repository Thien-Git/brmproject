package com.example.brmproject.service.imp;

import com.example.brmproject.domain.dto.BookDTO;
import com.example.brmproject.domain.entities.BookEntity;
import com.example.brmproject.repositories.BookEntityRepository;
import com.example.brmproject.service.BookService;
import com.example.brmproject.ultilities.SD.BookDetailStatus;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class BookServiceImp  implements BookService {

    ModelMapper modelMapper;
    BookEntityRepository bookRepo;

    @Autowired
    public BookServiceImp(ModelMapper modelMapper, BookEntityRepository bookRepo) {
        this.modelMapper = modelMapper;
        this.bookRepo = bookRepo;
    }





    @Override
    public List<BookDTO> findAll() {

        return bookRepo.findAll().stream().map(book -> countAvailable(book)).collect(Collectors.toList());
    }


    public BookDTO mapToDTO(BookEntity book) {
        BookDTO bookDTO = modelMapper.map(book, BookDTO.class);
        return bookDTO;

    }

    public BookEntity mapToEntity(BookDTO bookDTO) {
        BookEntity book = modelMapper.map(bookDTO, BookEntity.class);
        return book;

    }
    public BookDTO countAvailable(BookEntity book) {
        Long availableBook= book.getBookDetailsById().stream().filter(b->b.getStatus().equalsIgnoreCase(String.valueOf(BookDetailStatus.AVAILABLE))).count();
        //add count to book dto
        BookDTO bookDTO = modelMapper.map(book, BookDTO.class);
        bookDTO.setAvalableBook(availableBook);
        return bookDTO;
    }
}
